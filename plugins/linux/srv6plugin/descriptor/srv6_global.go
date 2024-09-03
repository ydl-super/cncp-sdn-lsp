package descriptor

import (
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
)

const (
	SRv6GlobalDescriptorName = "srv6_global"
)

type SRv6GlobalDescriptor struct {
	log               logging.Logger
	srv6GlobalHandler srv6linuxcalls.SRv6GlobalAPI
	ifPlugin          ifplugin.API
	nsPlugin          nsplugin.API
	addrAlloc         netalloc.AddressAllocator
	scheduler         kvs.KVScheduler

	// parallelization of the Retrieve operation
	goRoutinesCnt int
}

func NewSRv6GlobalDescriptor(
	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
	srv6GlobalHandler srv6linuxcalls.SRv6GlobalAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {

	ctx := &SRv6GlobalDescriptor{
		scheduler:         scheduler,
		srv6GlobalHandler: srv6GlobalHandler,
		ifPlugin:          ifPlugin,
		nsPlugin:          nsPlugin,
		addrAlloc:         addrAlloc,
		goRoutinesCnt:     goRoutinesCnt,
		log:               log.NewLogger("srv6-global-descriptor"),
	}

	typedDescr := &adapter.SRv6GlobalDescriptor{
		Name:          SRv6GlobalDescriptorName,
		NBKeyPrefix:   linux_srv6.ModelSRv6Global.KeyPrefix(),
		ValueTypeName: linux_srv6.ModelSRv6Global.ProtoName(),
		KeySelector:   linux_srv6.ModelSRv6Global.IsKeyValid,
		KeyLabel:      linux_srv6.ModelSRv6Global.StripKeyPrefix,
		Validate:      ctx.Validate,
		Create:        ctx.Create,
		Delete:        ctx.Delete,
		Update:        ctx.Update,
		RetrieveDependencies: []string{
			netalloc_descr.IPAllocDescriptorName,
			ifdescriptor.InterfaceDescriptorName},
	}
	return adapter.NewSRv6GlobalDescriptor(typedDescr)
}

func (d *SRv6GlobalDescriptor) Validate(key string, srv6Global *linux_srv6.SRv6Global) error {
	var err error

	switch srv6Global.Type {
	case "tunsrc":
		if srv6Global.Address == "" {
			err = errors.Errorf("Linux srv6 global defined without address reference %s", srv6Global.Address)
			d.log.Error(err)
			return err
		}
	case "hmac":
		if srv6Global.KeyId == "" {
			err = errors.Errorf("Linux srv6 global defined without key id reference %s", srv6Global.KeyId)
			d.log.Error(err)
			return err
		}
		if srv6Global.Algorithm == "" {
			err = errors.Errorf("Linux srv6 global defined without algorithm reference %s", srv6Global.Algorithm)
			d.log.Error(err)
			return err
		}
	default:
		err = errors.Errorf("unknown srv6 set type %s", srv6Global.Type)
		d.log.Error(err)
		return err

	}
	return nil
}

func (d *SRv6GlobalDescriptor) Create(key string, srv6Global *linux_srv6.SRv6Global) (metadata interface{}, err error) {
	output, err := d.srv6GlobalHandler.SetSRv6GlobalCommand(srv6Global)
	d.log.Info(output)
	return nil, err
}

func (d *SRv6GlobalDescriptor) Delete(key string, srv6Global *linux_srv6.SRv6Global, metadata interface{}) error {
	output, err := d.srv6GlobalHandler.SetSRv6GlobalCommand(srv6Global)
	d.log.Info(output)
	return err
}

func (d *SRv6GlobalDescriptor) Update(key string,
	oldSRv6Global, newSRv6Global *linux_srv6.SRv6Global, metadata interface{}) (newMetadata interface{}, err error) {
	output, err := d.srv6GlobalHandler.SetSRv6GlobalCommand(newSRv6Global)
	d.log.Info(output)
	return nil, err
}
