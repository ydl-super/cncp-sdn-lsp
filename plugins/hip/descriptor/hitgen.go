package descriptor

import (
	"go.ligato.io/cn-infra/v2/logging"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.pantheon.tech/stonework/plugins/hip/descriptor/adapter"
	"go.pantheon.tech/stonework/plugins/hip/hipcalls"
	"go.pantheon.tech/stonework/proto/hip"
)

const (
	HitgenCommondDescriptorName = "hitgen-descriptor"
)

type HipgenDescriptor struct {
	log           logging.Logger
	hipgenHandler hipcalls.HipOpenhipAPI
}

func NewHitgenCommondDescriptor(hipgenHandler hipcalls.HipOpenhipAPI, logger logging.PluginLogger) *kvs.KVDescriptor {
	ctx := &HipgenDescriptor{
		log:           logger.NewLogger("hitgen-descriptor"),
		hipgenHandler: hipgenHandler,
	}
	typedDescr := &adapter.HitgenDescriptor{
		Name:          HitgenCommondDescriptorName,
		NBKeyPrefix:   openhip_hip.ModelHitgen.KeyPrefix(),
		ValueTypeName: openhip_hip.ModelHitgen.ProtoName(),
		KeySelector:   openhip_hip.ModelHitgen.IsKeyValid,
		KeyLabel:      openhip_hip.ModelHitgen.StripKeyPrefix,
		Validate:      ctx.Validate,
		Create:        ctx.Create,
		Delete:        ctx.Delete,
	}
	return adapter.NewHitgenDescriptor(typedDescr)
}
func (d *HipgenDescriptor) Validate(key2 string, value *openhip_hip.HitgenCMD) error {
	if value.FilePath != "" {
		_, err := PathExists(value.FilePath)
		if err != nil {
			return err
		}
	}
	return nil
}
func (d *HipgenDescriptor) Create(key string, value *openhip_hip.HitgenCMD) (metadata interface{}, err error) {
	d.log.Info(d.hipgenHandler.SetHitgenCommond(value).Error())
	return nil, nil
}

func (d *HipgenDescriptor) Delete(key string, value *openhip_hip.HitgenCMD, metadata interface{}) error {
	d.log.Info(d.hipgenHandler.SetHitgenCommond(value).Error())
	return nil
}
