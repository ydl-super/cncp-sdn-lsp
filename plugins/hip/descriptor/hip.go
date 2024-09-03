package descriptor

import (
	"fmt"
	"go.ligato.io/cn-infra/v2/logging"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	adapter2 "go.pantheon.tech/stonework/plugins/hip/descriptor/adapter"
	openhip_hip "go.pantheon.tech/stonework/proto/hip"
	"net"
	"os"

	"go.pantheon.tech/stonework/plugins/hip/descriptor/adapter"
	"go.pantheon.tech/stonework/plugins/hip/hipcalls"
)

const (
	HipCommondDescriptorName = "hip-descriptor"
)

type HipDescriptor struct {
	log        logging.Logger
	hipHandler hipcalls.HipOpenhipAPI
}

func NewHipCommondDescriptor(hipHandler hipcalls.HipOpenhipAPI, logger logging.PluginLogger) *kvs.KVDescriptor {
	ctx := &HipDescriptor{
		log:        logger.NewLogger("hip-descriptor"),
		hipHandler: hipHandler,
	}
	typedDescr := &adapter2.HipDescriptor{
		Name:          HipCommondDescriptorName,
		NBKeyPrefix:   openhip_hip.ModelHip.KeyPrefix(),
		ValueTypeName: openhip_hip.ModelHip.ProtoName(),
		KeySelector:   openhip_hip.ModelHip.IsKeyValid,
		KeyLabel:      openhip_hip.ModelHip.StripKeyPrefix,
		Validate:      ctx.Validate,
		Create:        ctx.Create,
		Delete:        ctx.Delete,
	}
	return adapter.NewHipDescriptor(typedDescr)
}
func (d *HipDescriptor) Validate(key2 string, value *openhip_hip.HipCMD) error {
	if value.ConfPath != "" {
		_, err := PathExists(value.ConfPath)
		if err != nil {
			return err
		}
	}
	if value.TriggerAddress != "" {
		ip := net.ParseIP(value.TriggerAddress)
		if ip == nil {
			return fmt.Errorf("illegal trigger address %s", value.TriggerAddress)
		}
	}
	return nil
}
func (d *HipDescriptor) Create(key string, value *openhip_hip.HipCMD) (metadata interface{}, err error) {
	d.log.Info(d.hipHandler.SetHipCommond(value).Error())
	return nil, nil
}

func (d *HipDescriptor) Delete(key string, value *openhip_hip.HipCMD, metadata interface{}) error {
	d.log.Info(d.hipHandler.CloseHip().Error())
	return nil
}

// 判断所给路径文件/文件夹是否存在
func PathExists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	//isnotexist来判断，是不是不存在的错误
	if os.IsNotExist(err) { //如果返回的错误类型使用os.isNotExist()判断为true，说明文件或者文件夹不存在
		return false, nil
	}
	return false, err //如果有错误了，但是不是不存在的错误，所以把这个错误原封不动的返回
}
