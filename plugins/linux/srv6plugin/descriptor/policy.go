package descriptor

import (
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
	// PolicyDescriptorName is the name of the descriptor for Linux SRv6 policy.
	PolicyDescriptorName = "policy"
)

// A list of non-retriable errors:
var (
	ErrPolicyWithoutPrefix = errors.New("Linux srv6 policy defined without prefix reference")

	ErrPolicyWithoutEncapMode = errors.New("Linux srv6 policy defined without encapMode reference")

	ErrPolicyWithoutSegments = errors.New("Linux srv6 policy defined without segments reference")

	ErrPolicyWithoutDevice = errors.New("Linux srv6 policy defined without Device reference")
)

// PolicyDescriptor teaches KVScheduler how to configure Linux policy entries.
//type PolicyDescriptor struct {
//	log           logging.Logger
//	policyHandler srv6linuxcalls.NetlinkAPI
//	ifPlugin      ifplugin.API
//	nsPlugin      nsplugin.API
//	addrAlloc     netalloc.AddressAllocator
//	scheduler     kvs.KVScheduler
//
//	// parallelization of the Retrieve operation
//	goRoutinesCnt int
//}

type PolicyDescriptor struct {
	log           logging.Logger
	policyHandler srv6linuxcalls.PolicyAPI
	ifPlugin      ifplugin.API
	nsPlugin      nsplugin.API
	addrAlloc     netalloc.AddressAllocator
	scheduler     kvs.KVScheduler

	// parallelization of the Retrieve operation
	goRoutinesCnt int
}

func NewPolicyDescriptor(
	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
	policyHandler srv6linuxcalls.PolicyAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {

	ctx := &PolicyDescriptor{
		scheduler:     scheduler,
		policyHandler: policyHandler,
		ifPlugin:      ifPlugin,
		nsPlugin:      nsPlugin,
		addrAlloc:     addrAlloc,
		goRoutinesCnt: goRoutinesCnt,
		log:           log.NewLogger("policy-descriptor"),
	}

	typedDescr := &adapter.PolicyDescriptor{
		Name:            PolicyDescriptorName,
		NBKeyPrefix:     linux_srv6.ModelPolicy.KeyPrefix(),
		ValueTypeName:   linux_srv6.ModelPolicy.ProtoName(),
		KeySelector:     linux_srv6.ModelPolicy.IsKeyValid,
		KeyLabel:        linux_srv6.ModelPolicy.StripKeyPrefix,
		ValueComparator: ctx.EquivalentPolicies,
		Validate:        ctx.Validate,
		Create:          ctx.Create,
		Delete:          ctx.Delete,
		Update:          ctx.Update,
		//Retrieve:        ctx.Retrieve,
		//Dependencies:    ctx.Dependencies,
		RetrieveDependencies: []string{
			netalloc_descr.IPAllocDescriptorName,
			ifdescriptor.InterfaceDescriptorName},
	}
	return adapter.NewPolicyDescriptor(typedDescr)
}

// NewPolicyDescriptor creates a new instance of the policy descriptor.
//func NewPolicyDescriptor(
//	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
//	policyHandler srv6linuxcalls.NetlinkAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {
//
//	ctx := &PolicyDescriptor{
//		scheduler:     scheduler,
//		policyHandler: policyHandler,
//		ifPlugin:      ifPlugin,
//		nsPlugin:      nsPlugin,
//		addrAlloc:     addrAlloc,
//		goRoutinesCnt: goRoutinesCnt,
//		log:           log.NewLogger("policy-descriptor"),
//	}
//
//	typedDescr := &adapter.PolicyDescriptor{
//		Name:            PolicyDescriptorName,
//		NBKeyPrefix:     linux_srv6.ModelPolicy.KeyPrefix(),
//		ValueTypeName:   linux_srv6.ModelPolicy.ProtoName(),
//		KeySelector:     linux_srv6.ModelPolicy.IsKeyValid,
//		KeyLabel:        linux_srv6.ModelPolicy.StripKeyPrefix,
//		ValueComparator: ctx.EquivalentPolicies,
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
//	return adapter.NewPolicyDescriptor(typedDescr)
//}

func (d *PolicyDescriptor) EquivalentPolicies(key string, oldPolicy, NewPolicy *linux_srv6.Policy) bool {
	// compare sid case-insensitively
	return strings.ToLower(oldPolicy.Prefix) == strings.ToLower(NewPolicy.Prefix) &&
		strings.ToLower(oldPolicy.Device) == strings.ToLower(NewPolicy.Device)
}

// Validate validates policy configuration.
func (d *PolicyDescriptor) Validate(key string, policy *linux_srv6.Policy) (err error) {
	if policy.Prefix == "" {
		return kvs.NewInvalidValueError(ErrPolicyWithoutPrefix, "prefix")
	}
	if policy.EncapMode == "" {
		return kvs.NewInvalidValueError(ErrPolicyWithoutEncapMode, "encapMode")
	}
	if len(policy.Segments) == 0 {
		return kvs.NewInvalidValueError(ErrPolicyWithoutSegments, "segments")
	}
	if policy.Device == "" {
		return kvs.NewInvalidValueError(ErrPolicyWithoutDevice, "device")
	}

	return nil
}

// Create creates policy entry.
func (d *PolicyDescriptor) Create(key string, policy *linux_srv6.Policy) (metadata interface{}, err error) {
	//err = d.updatePolicy(policy, "add", d.policyHandler.AddRoute)
	//return nil, err
	output, err := d.policyHandler.SetPolicyCommand(cncpexec.ActionAdd, policy)
	d.log.Info(output)
	return nil, err
}

// Delete removes policy entry.
func (d *PolicyDescriptor) Delete(key string, policy *linux_srv6.Policy, metadata interface{}) error {
	//return d.updatePolicy(policy, "delete", d.policyHandler.DelRoute)
	output, err := d.policyHandler.SetPolicyCommand(cncpexec.ActionDelete, policy)
	d.log.Info(output)
	return err
}

func (d *PolicyDescriptor) Update(key string, oldPolicy, newPolicy *linux_srv6.Policy, oldMetadata interface{}) (newMetadata interface{}, err error) {
	//err = d.updatePolicy(newPolicy, "modify", d.policyHandler.ReplaceRoute)
	//return nil, err
	output, err := d.policyHandler.SetPolicyCommand(cncpexec.ActionDelete, oldPolicy)
	if err != nil {
		return nil, err
	}
	output, err = d.policyHandler.SetPolicyCommand(cncpexec.ActionAdd, newPolicy)
	if err != nil {
		return nil, err
	}
	d.log.Info(output)
	return nil, err
}

// updatePolicy adds, modifies or deletes an policy entry.
//func (d *PolicyDescriptor) updatePolicy(policy *linux_srv6.Policy, actionName string, actionClb func(arpEntry *netlink.Route) error) error {
//	var err error
//
//	// Prepare policy entry object
//	netlinkRoute := &netlink.Route{}
//
//	// Get interface metadata
//	ifMeta, found := d.ifPlugin.GetInterfaceIndex().LookupByName(policy.Device)
//	if !found || ifMeta == nil {
//		err = errors.Errorf("failed to obtain metadata for interface %s", policy.Device)
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
//	seg6Encap := &netlink.SEG6Encap{}
//
//	seg6Encap.Segments = make([]net.IP, 0)
//
//	for _, segment := range policy.Segments {
//		ip := net.ParseIP(segment)
//		ipv6 := ip.To16()
//		if ipv6 != nil {
//			seg6Encap.Segments = append(seg6Encap.Segments, ipv6)
//		}
//	}
//
//	if policy.EncapMode == "inline" {
//		seg6Encap.Mode = nl.SEG6_IPTUN_MODE_INLINE
//	} else {
//		seg6Encap.Mode = nl.SEG6_IPTUN_MODE_ENCAP
//	}
//
//	netlinkRoute.Encap = seg6Encap
//
//	// update route in the interface namespace
//	err = actionClb(netlinkRoute)
//	if err != nil {
//		err = errors.Errorf("failed to %s linux seg6 policy: %v", actionName, err)
//		d.log.Error(err)
//		return err
//	}
//
//	return nil
//}
//
//// Dependencies lists dependencies for a Linux policy.
//func (d *PolicyDescriptor) Dependencies(key string, policy *linux_srv6.Policy) []kvs.Dependency {
//	var dependencies []kvs.Dependency
//	// the outgoing interface must exist and be UP
//	if policy.Device != "" {
//		dependencies = append(dependencies, kvs.Dependency{
//			Label: routeOutInterfaceDep,
//			Key:   ifmodel.InterfaceStateKey(policy.Device, true),
//		})
//	}
//	if policy.Device != "" {
//		// route also requires the interface to be in the L3 mode (have at least one IP address assigned)
//		dependencies = append(dependencies, kvs.Dependency{
//			Label: routeOutInterfaceIPAddrDep,
//			AnyOf: kvs.AnyOfDependency{
//				KeyPrefixes: []string{
//					ifmodel.InterfaceAddressPrefix(policy.Device),
//				},
//			},
//		})
//	}
//	return dependencies
//}
//
//// Retrieve returns all routes associated with interfaces managed by this agent.
//func (d *PolicyDescriptor) Retrieve(correlate []adapter.PolicyKVWithMetadata) ([]adapter.PolicyKVWithMetadata, error) {
//	var values []adapter.PolicyKVWithMetadata
//
//	// prepare expected configuration with de-referenced netalloc links
//	nbCfg := make(map[string]*linux_srv6.Policy)
//	expCfg := make(map[string]*linux_srv6.Policy)
//	for _, kv := range correlate {
//		prefix := kv.Value.Prefix
//		parsed, err := d.addrAlloc.GetOrParseIPAddress(kv.Value.Prefix,
//			"", netalloc_api.IPAddressForm_ADDR_NET)
//		if err == nil {
//			prefix = parsed.String()
//		}
//		policy := proto.Clone(kv.Value).(*linux_srv6.Policy)
//		policy.Prefix = prefix
//		key := models.Key(policy)
//		expCfg[key] = policy
//		nbCfg[key] = kv.Value
//	}
//
//	policyDetails, err := d.policyHandler.DumpPolicies()
//	if err != nil {
//		return nil, errors.Errorf("Failed to retrieve linux ARPs: %v", err)
//	}
//
//	// correlate with the expected configuration
//	for _, policyDetail := range policyDetails {
//		policy := adapter.PolicyKVWithMetadata{
//			Key: linux_srv6.PolicyKey(policyDetail.Policy.Prefix, policyDetail.Policy.Device),
//			Value: &linux_srv6.Policy{
//				Prefix:    policyDetail.Policy.Prefix,
//				Device:    policyDetail.Policy.Device,
//				Segments:  policyDetail.Policy.Segments,
//				EncapMode: policyDetail.Policy.EncapMode,
//			},
//			Origin: kvs.UnknownOrigin, // let the scheduler to determine the origin
//		}
//
//		key := linux_srv6.PolicyKey(policyDetail.Policy.Prefix, policyDetail.Policy.Device)
//		if expCfg, hasExpCfg := expCfg[key]; hasExpCfg {
//			if d.EquivalentPolicies(key, policy.Value, expCfg) {
//				policy.Value = nbCfg[key]
//				// recreate the key in case the dest. IP was replaced with netalloc link
//				policy.Key = models.Key(policy.Value)
//			}
//		}
//		values = append(values, policy)
//	}
//
//	return values, nil
//}
