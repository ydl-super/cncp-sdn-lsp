package descriptor

import (
	"golang.org/x/sys/unix"

	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
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
	// BlackHoleRouteDescriptorName is the name of the descriptor for Linux SRv6 policy.
	BlackHoleRouteDescriptorName = "blackhole_route"
)

// A list of non-retriable errors:
var (
	ErrBlackHoleRouteWithoutTableId = errors.New("Linux srv6 blackhole route defined without table id reference")
)

//// BlackHoleRouteDescriptor teaches KVScheduler how to configure Linux BlackHoleRoute entries.
//type BlackHoleRouteDescriptor struct {
//	log                   logging.Logger
//	blackholeRouteHandler srv6linuxcalls.NetlinkAPI
//	ifPlugin              ifplugin.API
//	nsPlugin              nsplugin.API
//	addrAlloc             netalloc.AddressAllocator
//	scheduler             kvs.KVScheduler
//
//	// parallelization of the Retrieve operation
//	goRoutinesCnt int
//}
//
//// NewBlackHoleRouteDescriptor creates a new instance of the policy descriptor.
//func NewBlackHoleRouteDescriptor(
//	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
//	blackholeRouteHandler srv6linuxcalls.NetlinkAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {
//
//	ctx := &BlackHoleRouteDescriptor{
//		scheduler:             scheduler,
//		blackholeRouteHandler: blackholeRouteHandler,
//		ifPlugin:              ifPlugin,
//		nsPlugin:              nsPlugin,
//		addrAlloc:             addrAlloc,
//		goRoutinesCnt:         goRoutinesCnt,
//		log:                   log.NewLogger("blackholeRoute-descriptor"),
//	}
//
//	typedDescr := &adapter.BlackHoleRouteDescriptor{
//		Name:            BlackHoleRouteDescriptorName,
//		NBKeyPrefix:     linux_srv6.ModelBlackHoleRoute.KeyPrefix(),
//		ValueTypeName:   linux_srv6.ModelBlackHoleRoute.ProtoName(),
//		KeySelector:     linux_srv6.ModelBlackHoleRoute.IsKeyValid,
//		KeyLabel:        linux_srv6.ModelBlackHoleRoute.StripKeyPrefix,
//		ValueComparator: ctx.EquivalentBlackHoleRoutes,
//		Validate:        ctx.Validate,
//		Create:          ctx.Create,
//		Delete:          ctx.Delete,
//		Update:          ctx.Update,
//		RetrieveDependencies: []string{
//			netalloc_descr.IPAllocDescriptorName,
//			ifdescriptor.InterfaceDescriptorName},
//	}
//	return adapter.NewBlackHoleRouteDescriptor(typedDescr)
//}

// BlackHoleRouteDescriptor teaches KVScheduler how to configure Linux BlackHoleRoute entries.
type BlackHoleRouteDescriptor struct {
	log                   logging.Logger
	blackholeRouteHandler srv6linuxcalls.BlackHoleRouteAPI
	ifPlugin              ifplugin.API
	nsPlugin              nsplugin.API
	addrAlloc             netalloc.AddressAllocator
	scheduler             kvs.KVScheduler

	// parallelization of the Retrieve operation
	goRoutinesCnt int
}

// NewBlackHoleRouteDescriptor creates a new instance of the policy descriptor.
func NewBlackHoleRouteDescriptor(
	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
	blackholeRouteHandler srv6linuxcalls.BlackHoleRouteAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {

	ctx := &BlackHoleRouteDescriptor{
		scheduler:             scheduler,
		blackholeRouteHandler: blackholeRouteHandler,
		ifPlugin:              ifPlugin,
		nsPlugin:              nsPlugin,
		addrAlloc:             addrAlloc,
		goRoutinesCnt:         goRoutinesCnt,
		log:                   log.NewLogger("blackholeRoute-descriptor"),
	}

	typedDescr := &adapter.BlackHoleRouteDescriptor{
		Name:            BlackHoleRouteDescriptorName,
		NBKeyPrefix:     linux_srv6.ModelBlackHoleRoute.KeyPrefix(),
		ValueTypeName:   linux_srv6.ModelBlackHoleRoute.ProtoName(),
		KeySelector:     linux_srv6.ModelBlackHoleRoute.IsKeyValid,
		KeyLabel:        linux_srv6.ModelBlackHoleRoute.StripKeyPrefix,
		ValueComparator: ctx.EquivalentBlackHoleRoutes,
		Validate:        ctx.Validate,
		Create:          ctx.Create,
		Delete:          ctx.Delete,
		Update:          ctx.Update,
		RetrieveDependencies: []string{
			netalloc_descr.IPAllocDescriptorName,
			ifdescriptor.InterfaceDescriptorName},
	}
	return adapter.NewBlackHoleRouteDescriptor(typedDescr)
}

func (d *BlackHoleRouteDescriptor) EquivalentBlackHoleRoutes(key string,
	oldBlackHoleRoute, NewBlackHoleRoute *linux_srv6.BlackHoleRoute) bool {
	// compare sid case-insensitively
	return oldBlackHoleRoute.TableId == NewBlackHoleRoute.TableId
}

// Validate validates policy configuration.
func (d *BlackHoleRouteDescriptor) Validate(key string, blackholeRoute *linux_srv6.BlackHoleRoute) (err error) {
	if blackholeRoute.TableId < 0 || blackholeRoute.TableId > 255 {
		return kvs.NewInvalidValueError(ErrBlackHoleRouteWithoutTableId, "table id")
	}

	return nil
}

// Create creates blackhole route entry.
func (d *BlackHoleRouteDescriptor) Create(key string, blackholeRoute *linux_srv6.BlackHoleRoute) (metadata interface{}, err error) {
	//err = d.updateBlackHoleRoute(blackholeRoute, "add", d.blackholeRouteHandler.AddRoute)
	//return nil, err
	output, err := d.blackholeRouteHandler.SetBlackHoleRouteCommand(cncpexec.ActionAdd, blackholeRoute)
	d.log.Info(output)
	return nil, err
}

// Delete removes policy entry.
func (d *BlackHoleRouteDescriptor) Delete(key string, blackholeRoute *linux_srv6.BlackHoleRoute, metadata interface{}) error {
	//return d.updateBlackHoleRoute(blackholeRoute, "delete", d.blackholeRouteHandler.DelRoute)
	output, err := d.blackholeRouteHandler.SetBlackHoleRouteCommand(cncpexec.ActionDelete, blackholeRoute)
	d.log.Info(output)
	return err
}

func (d *BlackHoleRouteDescriptor) Update(key string, oldBlackHoleRoute, newBlackHoleRoute *linux_srv6.BlackHoleRoute, oldMetadata interface{}) (newMetadata interface{}, err error) {
	//err = d.updateBlackHoleRoute(newBlackHoleRoute, "modify", d.blackholeRouteHandler.ReplaceRoute)
	//return nil, err
	output, err := d.blackholeRouteHandler.SetBlackHoleRouteCommand(cncpexec.ActionDelete, oldBlackHoleRoute)
	if err != nil {
		return nil, err
	}
	output, err = d.blackholeRouteHandler.SetBlackHoleRouteCommand(cncpexec.ActionAdd, newBlackHoleRoute)
	if err != nil {
		return nil, err
	}
	d.log.Info(output)
	return nil, err
}

// updateBlackHoleRoute adds, modifies or deletes an blackhole route entry.
func (d *BlackHoleRouteDescriptor) updateBlackHoleRoute(blackholeRoute *linux_srv6.BlackHoleRoute,
	actionName string, actionClb func(routeEntry *netlink.Route) error) error {
	var err error

	// Prepare policy entry object
	netlinkRoute := &netlink.Route{}

	netlinkRoute.Type = unix.RTN_BLACKHOLE
	netlinkRoute.Table = int(blackholeRoute.TableId)

	// update route in the interface namespace
	err = actionClb(netlinkRoute)
	if err != nil {
		err = errors.Errorf("failed to %s linux seg6 policy: %v", actionName, err)
		d.log.Error(err)
		return err
	}

	return nil
}
