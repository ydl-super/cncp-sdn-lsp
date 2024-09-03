package descriptor

import (
	"net"
	"strings"

	"github.com/pkg/errors"
	"go.ligato.io/cn-infra/v2/logging"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.ligato.io/vpp-agent/v3/plugins/linux/ifplugin"
	ifdescriptor "go.ligato.io/vpp-agent/v3/plugins/linux/ifplugin/descriptor"
	"go.ligato.io/vpp-agent/v3/plugins/linux/nsplugin"
	"go.ligato.io/vpp-agent/v3/plugins/netalloc"
	netalloc_descr "go.ligato.io/vpp-agent/v3/plugins/netalloc/descriptor"

	"go.pantheon.tech/stonework/plugins/linux/srv6plugin/descriptor/adapter"
	srv6linuxcalls "go.pantheon.tech/stonework/plugins/linux/srv6plugin/linuxcalls"
	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
	cncpexec "go.pantheon.tech/stonework/utils/exec"
)

const (
	// LocalSIDDescriptorName is the name of the descriptor for Linux SRv6 LocalSID.
	LocalSIDDescriptorName = "localsid"

	// dependency labels
	routeOutInterfaceDep       = "outgoing-interface-is-up"
	routeOutInterfaceIPAddrDep = "outgoing-interface-has-ip-address"
	routeGwReachabilityDep     = "gw-reachable"
	allocatedAddrAttached      = "allocated-addr-attached"

	// default metric of the IPv6 route
	ipv6DefaultMetric = 1024
)

// A list of non-retriable errors:
var (
	ErrLocalSIDWithoutSID = errors.New("Linux srv6 localsid defined without sid reference")

	ErrLocalSIDWithoutDevice = errors.New("Linux srv6 localsid defined without device reference")

	ErrLocalSIDWithoutEndFunction = errors.New("Linux srv6 localsid defined without end function reference")
)

// LocalSIDDescriptor teaches KVScheduler how to configure Linux LocalSID entries.
//type LocalSIDDescriptor struct {
//	log             logging.Logger
//	localSIDHandler srv6linuxcalls.NetlinkAPI
//	ifPlugin        ifplugin.API
//	nsPlugin        nsplugin.API
//	addrAlloc       netalloc.AddressAllocator
//	scheduler       kvs.KVScheduler
//
//	// parallelization of the Retrieve operation
//	goRoutinesCnt int
//}

type LocalSIDDescriptor struct {
	log             logging.Logger
	localSIDHandler srv6linuxcalls.LocalSIDAPI
	ifPlugin        ifplugin.API
	nsPlugin        nsplugin.API
	addrAlloc       netalloc.AddressAllocator
	scheduler       kvs.KVScheduler

	// parallelization of the Retrieve operation
	goRoutinesCnt int
}

func NewLocalSIDDescriptor(
	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
	localSIDHandler srv6linuxcalls.LocalSIDAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {

	ctx := &LocalSIDDescriptor{
		scheduler:       scheduler,
		localSIDHandler: localSIDHandler,
		ifPlugin:        ifPlugin,
		nsPlugin:        nsPlugin,
		addrAlloc:       addrAlloc,
		goRoutinesCnt:   goRoutinesCnt,
		log:             log.NewLogger("localsid-descriptor"),
	}

	typedDescr := &adapter.LocalSIDDescriptor{
		Name:          LocalSIDDescriptorName,
		NBKeyPrefix:   linux_srv6.ModelLocalSID.KeyPrefix(),
		ValueTypeName: linux_srv6.ModelLocalSID.ProtoName(),
		KeySelector:   linux_srv6.ModelLocalSID.IsKeyValid,
		KeyLabel:      linux_srv6.ModelLocalSID.StripKeyPrefix,
		Validate:      ctx.Validate,
		Create:        ctx.Create,
		Delete:        ctx.Delete,
		Update:        ctx.Update,
		RetrieveDependencies: []string{
			netalloc_descr.IPAllocDescriptorName,
			ifdescriptor.InterfaceDescriptorName},
	}
	return adapter.NewLocalSIDDescriptor(typedDescr)
}

// NewLocalSIDDescriptor creates a new instance of the LocalSID descriptor.
//func NewLocalSIDDescriptor(
//	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
//	localSIDHandler srv6linuxcalls.NetlinkAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {
//
//	ctx := &LocalSIDDescriptor{
//		scheduler:       scheduler,
//		localSIDHandler: localSIDHandler,
//		ifPlugin:        ifPlugin,
//		nsPlugin:        nsPlugin,
//		addrAlloc:       addrAlloc,
//		goRoutinesCnt:   goRoutinesCnt,
//		log:             log.NewLogger("localsid-descriptor"),
//	}
//
//	typedDescr := &adapter.LocalSIDDescriptor{
//		Name:            LocalSIDDescriptorName,
//		NBKeyPrefix:     linux_srv6.ModelLocalSID.KeyPrefix(),
//		ValueTypeName:   linux_srv6.ModelLocalSID.ProtoName(),
//		KeySelector:     linux_srv6.ModelLocalSID.IsKeyValid,
//		KeyLabel:        linux_srv6.ModelLocalSID.StripKeyPrefix,
//		ValueComparator: ctx.EquivalentLocalSIDs,
//		Validate:        ctx.Validate,
//		Create:          ctx.Create,
//		Delete:          ctx.Delete,
//		Update:          ctx.Update,
//		Retrieve:        ctx.Retrieve,
//		Dependencies:    ctx.Dependencies,
//		RetrieveDependencies: []string{
//			netalloc_descr.IPAllocDescriptorName,
//			ifdescriptor.InterfaceDescriptorName},
//	}
//	return adapter.NewLocalSIDDescriptor(typedDescr)
//}

func (d *LocalSIDDescriptor) EquivalentLocalSIDs(key string, oldLocalSID, newLocalSID *linux_srv6.LocalSID) bool {
	// attributes compared as usually:
	if oldLocalSID.Device != newLocalSID.Device {
		return false
	}
	// compare sid case-insensitively
	return strings.ToLower(oldLocalSID.Sid) == strings.ToLower(newLocalSID.Sid)
}

// Validate validates LocalSID configuration.
func (d *LocalSIDDescriptor) Validate(key string, localSID *linux_srv6.LocalSID) (err error) {
	if localSID.Sid == "" {
		return kvs.NewInvalidValueError(ErrLocalSIDWithoutSID, "sid")
	}
	if localSID.Device == "" {
		return kvs.NewInvalidValueError(ErrLocalSIDWithoutDevice, "device")
	}
	if localSID.EndFunction == nil {
		return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function")
	}
	switch ef := localSID.EndFunction.(type) {
	case *linux_srv6.LocalSID_BaseEndFunction:
	case *linux_srv6.LocalSID_EndFunctionX:
		_, err := ParseIPv6(ef.EndFunctionX.NextHop)
		if err != nil {
			return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function_x")
		}
	case *linux_srv6.LocalSID_EndFunctionT:
	case *linux_srv6.LocalSID_EndFunctionDx2:
		if ef.EndFunctionDx2.OutgoingInterface == "" {
			return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function_dx2")
		}
	case *linux_srv6.LocalSID_EndFunctionDx4:
		_, err := ParseIPv4(ef.EndFunctionDx4.NextHop)
		if err != nil {
			return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function")
		}
	case *linux_srv6.LocalSID_EndFunctionDx6:
		_, err := ParseIPv6(ef.EndFunctionDx6.NextHop)
		if err != nil {
			return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function")
		}
	case *linux_srv6.LocalSID_EndFunctionDt4:
	case *linux_srv6.LocalSID_EndFunctionDt6:
	case *linux_srv6.LocalSID_EndFunctionB6:
		if len(ef.EndFunctionB6.Segments) == 0 {
			return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function_b6")
		}
	case *linux_srv6.LocalSID_EndFunctionB6Encaps:
		if len(ef.EndFunctionB6Encaps.Segments) == 0 {
			return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function_b6_encaps")
		}
	case nil:
		return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function")
	default:
		return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function")
	}
	return nil
}

// Create creates localSID entry.
func (d *LocalSIDDescriptor) Create(key string, localSID *linux_srv6.LocalSID) (metadata interface{}, err error) {
	//err = d.updateLocalSID(localSID, "add", d.localSIDHandler.AddRoute)
	//return nil, err
	output, err := d.localSIDHandler.SetLocalSIDCommand(cncpexec.ActionAdd, localSID)
	d.log.Info(output)
	return nil, err
}

// Delete removes localSID entry.
func (d *LocalSIDDescriptor) Delete(key string, localSID *linux_srv6.LocalSID, metadata interface{}) error {
	//return d.updateLocalSID(localSID, "delete", d.localSIDHandler.DelRoute)
	output, err := d.localSIDHandler.SetLocalSIDCommand(cncpexec.ActionDelete, localSID)
	d.log.Info(output)
	return err
}

func (d *LocalSIDDescriptor) Update(key string, oldLocalSID, newLocalSID *linux_srv6.LocalSID, oldMetadata interface{}) (newMetadata interface{}, err error) {
	//err = d.updateLocalSID(newLocalSID, "modify", d.localSIDHandler.ReplaceRoute)
	//return nil, err
	output, err := d.localSIDHandler.SetLocalSIDCommand(cncpexec.ActionDelete, oldLocalSID)
	if err != nil {
		return nil, err
	}
	output, err = d.localSIDHandler.SetLocalSIDCommand(cncpexec.ActionAdd, newLocalSID)
	if err != nil {
		return nil, err
	}
	d.log.Info(output)
	return nil, err
}

//// updateLocalSID adds, modifies or deletes an localSID entry.
//func (d *LocalSIDDescriptor) updateLocalSID(localSID *linux_srv6.LocalSID, actionName string, actionClb func(arpEntry *netlink.Route) error) error {
//	var err error
//
//	// Prepare ARP entry object
//	netlinkRoute := &netlink.Route{}
//
//	// Get interface metadata
//	ifMeta, found := d.ifPlugin.GetInterfaceIndex().LookupByName(localSID.Device)
//	if !found || ifMeta == nil {
//		err = errors.Errorf("failed to obtain metadata for interface %s", localSID.Device)
//		d.log.Error(err)
//		return err
//	}
//
//	// set link index
//	netlinkRoute.LinkIndex = ifMeta.LinuxIfIndex
//
//	// set routing table
//	if ifMeta.VrfMasterIf != "" {
//		// - route depends on interface having an IP address
//		// - IP address depends on the interface already being in the VRF
//		// - VRF assignment depends on the VRF device being configured
//		// => conclusion: VRF device is configured at this point
//		vrfMeta, found := d.ifPlugin.GetInterfaceIndex().LookupByName(ifMeta.VrfMasterIf)
//		if !found || vrfMeta == nil {
//			err = errors.Errorf("failed to obtain metadata for VRF device %s", ifMeta.VrfMasterIf)
//			d.log.Error(err)
//			return err
//		}
//		netlinkRoute.Table = int(vrfMeta.VrfDevRT)
//	}
//
//	seg6LocalEncap := &netlink.SEG6LocalEncap{}
//
//	// sid is ipNet
//	_, ipNet, err := net.ParseCIDR(localSID.Sid)
//	if err != nil {
//		err = errors.Errorf("failed to obtain sid %s", localSID.Sid)
//		d.log.Error(err)
//	}
//	netlinkRoute.Dst = ipNet
//	// sid is ip
//	if ipNet == nil {
//		netlinkRoute.Dst.IP = net.ParseIP(localSID.Sid)
//	}
//
//	switch localSID.EndFunction.(type) {
//	case *linux_srv6.LocalSID_BaseEndFunction:
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END
//	case *linux_srv6.LocalSID_EndFunctionX:
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END_X
//		ip := net.ParseIP(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionX).EndFunctionX.NextHop)
//		if ip.To4() == nil && ip.To16() != nil {
//			seg6LocalEncap.In6Addr = ip
//		} else {
//			seg6LocalEncap.InAddr = ip
//		}
//	case *linux_srv6.LocalSID_EndFunctionT:
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END_T
//		seg6LocalEncap.Table = int(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionT).EndFunctionT.VrfId)
//	case *linux_srv6.LocalSID_EndFunctionDx2:
//		// TODO: Add params
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END_DX2
//	case *linux_srv6.LocalSID_EndFunctionDx4:
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END_DX4
//		ip := net.ParseIP(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx4).EndFunctionDx4.NextHop)
//		if ip.To4() == nil && ip.To16() != nil {
//			seg6LocalEncap.In6Addr = ip
//		} else {
//			seg6LocalEncap.InAddr = ip
//		}
//	case *linux_srv6.LocalSID_EndFunctionDx6:
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END_DX6
//		ip := net.ParseIP(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx6).EndFunctionDx6.NextHop)
//		if ip.To4() == nil && ip.To16() != nil {
//			seg6LocalEncap.In6Addr = ip
//		} else {
//			seg6LocalEncap.InAddr = ip
//		}
//	case *linux_srv6.LocalSID_EndFunctionDt4:
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END_DT4
//		seg6LocalEncap.Table = int(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDt4).EndFunctionDt4.VrfId)
//	case *linux_srv6.LocalSID_EndFunctionDt6:
//		seg6LocalEncap.Action = nl.SEG6_LOCAL_ACTION_END_DT6
//		seg6LocalEncap.Table = int(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDt6).EndFunctionDt6.VrfId)
//	default:
//		return kvs.NewInvalidValueError(ErrLocalSIDWithoutEndFunction, "end_function")
//	}
//
//	netlinkRoute.Encap = seg6LocalEncap
//
//	// update route in the interface namespace
//	err = actionClb(netlinkRoute)
//	if err != nil {
//		err = errors.Errorf("failed to %s linux route: %v", actionName, err)
//		d.log.Error(err)
//		return err
//	}
//
//	return nil
//}
//
//// Dependencies lists dependencies for a Linux route.
//func (d *LocalSIDDescriptor) Dependencies(key string, localSID *linux_srv6.LocalSID) []kvs.Dependency {
//	var dependencies []kvs.Dependency
//	// the outgoing interface must exist and be UP
//	if localSID.Device != "" {
//		dependencies = append(dependencies, kvs.Dependency{
//			Label: routeOutInterfaceDep,
//			Key:   ifmodel.InterfaceStateKey(localSID.Device, true),
//		})
//	}
//	if localSID.Device != "" {
//		// route also requires the interface to be in the L3 mode (have at least one IP address assigned)
//		dependencies = append(dependencies, kvs.Dependency{
//			Label: routeOutInterfaceIPAddrDep,
//			AnyOf: kvs.AnyOfDependency{
//				KeyPrefixes: []string{
//					ifmodel.InterfaceAddressPrefix(localSID.Device),
//				},
//			},
//		})
//	}
//	return dependencies
//}
//
//// Retrieve returns all routes associated with interfaces managed by this agent.
//func (d *LocalSIDDescriptor) Retrieve(correlate []adapter.LocalSIDKVWithMetadata) ([]adapter.LocalSIDKVWithMetadata, error) {
//	var values []adapter.LocalSIDKVWithMetadata
//
//	// prepare expected configuration with de-referenced netalloc links
//	nbCfg := make(map[string]*linux_srv6.LocalSID)
//	expCfg := make(map[string]*linux_srv6.LocalSID)
//	for _, kv := range correlate {
//		sid := kv.Value.Sid
//		parsed, err := d.addrAlloc.GetOrParseIPAddress(kv.Value.Sid,
//			"", netalloc_api.IPAddressForm_ADDR_NET)
//		if err == nil {
//			sid = parsed.String()
//		}
//		localSID := proto.Clone(kv.Value).(*linux_srv6.LocalSID)
//		localSID.Sid = sid
//		key := models.Key(localSID)
//		expCfg[key] = localSID
//		nbCfg[key] = kv.Value
//	}
//
//	routeDetails, err := d.localSIDHandler.DumpRoutes()
//	if err != nil {
//		return nil, errors.Errorf("Failed to retrieve linux ARPs: %v", err)
//	}
//
//	// correlate with the expected configuration
//	for _, routeDetails := range routeDetails {
//		route := adapter.LocalSIDKVWithMetadata{
//			Key: linux_srv6.LocalSIDKey(routeDetails.Route.Sid, routeDetails.Route.Device),
//			Value: &linux_srv6.LocalSID{
//				Sid:         routeDetails.Route.Sid,
//				Device:      routeDetails.Route.Device,
//				EndFunction: routeDetails.Route.EndFunction,
//			},
//			Origin: kvs.UnknownOrigin, // let the scheduler to determine the origin
//		}
//
//		key := linux_srv6.LocalSIDKey(routeDetails.Route.Sid, routeDetails.Route.Device)
//		if expCfg, hasExpCfg := expCfg[key]; hasExpCfg {
//			if d.EquivalentLocalSIDs(key, route.Value, expCfg) {
//				route.Value = nbCfg[key]
//				// recreate the key in case the dest. IP was replaced with netalloc link
//				route.Key = models.Key(route.Value)
//			}
//		}
//		values = append(values, route)
//	}
//
//	return values, nil
//}

// ParseIPv4 parses string <str> to IPv4 address
func ParseIPv4(str string) (net.IP, error) {
	ip := net.ParseIP(str)
	if ip == nil {
		return nil, errors.Errorf(" %q is not ip address", str)
	}
	ipv4 := ip.To4()
	if ipv4 == nil {
		return nil, errors.Errorf(" %q is not ipv4 address", str)
	}
	return ipv4, nil
}

// ParseIPv6 parses string <str> to IPv6 address (including IPv4 address converted to IPv6 address)
func ParseIPv6(str string) (net.IP, error) {
	ip := net.ParseIP(str)
	if ip == nil {
		return nil, errors.Errorf(" %q is not ip address", str)
	}
	ipv6 := ip.To16()
	if ipv6 == nil {
		return nil, errors.Errorf(" %q is not ipv6 address", str)
	}
	return ipv6, nil
}
