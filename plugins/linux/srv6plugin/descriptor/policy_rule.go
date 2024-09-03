package descriptor

import (
	"net"
	"strings"

	"github.com/pkg/errors"
	netlink "github.com/vishvananda/netlink"
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
	// PolicyRuleDescriptorName is the name of the descriptor for Linux SRv6 policy rule.
	PolicyRuleDescriptorName = "policy_rule"
)

// A list of non-retriable errors:
var (
	ErrPolicyRuleWithoutPrefix = errors.New("Linux srv6 policy defined without prefix reference")

	ErrPolicyRuleWithoutTableId = errors.New("Linux srv6 policy defined without table id reference")
)

// PolicyRuleDescriptor teaches KVScheduler how to configure Linux policy rule entries.
//type PolicyRuleDescriptor struct {
//	log               logging.Logger
//	policyRuleHandler srv6linuxcalls.NetlinkAPI
//	ifPlugin          ifplugin.API
//	nsPlugin          nsplugin.API
//	addrAlloc         netalloc.AddressAllocator
//	scheduler         kvs.KVScheduler
//
//	// parallelization of the Retrieve operation
//	goRoutinesCnt int
//}
//
//// NewPolicyRuleDescriptor creates a new instance of the policy descriptor.
//func NewPolicyRuleDescriptor(
//	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
//	policyRuleHandler srv6linuxcalls.NetlinkAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {
//
//	ctx := &PolicyRuleDescriptor{
//		scheduler:         scheduler,
//		policyRuleHandler: policyRuleHandler,
//		ifPlugin:          ifPlugin,
//		nsPlugin:          nsPlugin,
//		addrAlloc:         addrAlloc,
//		goRoutinesCnt:     goRoutinesCnt,
//		log:               log.NewLogger("policy-rule-descriptor"),
//	}
//
//	typedDescr := &adapter.PolicyRuleDescriptor{
//		Name:            PolicyRuleDescriptorName,
//		NBKeyPrefix:     linux_srv6.ModelPolicyRule.KeyPrefix(),
//		ValueTypeName:   linux_srv6.ModelPolicyRule.ProtoName(),
//		KeySelector:     linux_srv6.ModelPolicyRule.IsKeyValid,
//		KeyLabel:        linux_srv6.ModelPolicyRule.StripKeyPrefix,
//		ValueComparator: ctx.EquivalentPolicies,
//		Validate:        ctx.Validate,
//		Create:          ctx.Create,
//		Delete:          ctx.Delete,
//		Update:          ctx.Update,
//		RetrieveDependencies: []string{
//			netalloc_descr.IPAllocDescriptorName,
//			ifdescriptor.InterfaceDescriptorName},
//	}
//	return adapter.NewPolicyRuleDescriptor(typedDescr)
//}

// PolicyRuleDescriptor teaches KVScheduler how to configure Linux policy rule entries.
type PolicyRuleDescriptor struct {
	log               logging.Logger
	policyRuleHandler srv6linuxcalls.PolicyRuleAPI
	ifPlugin          ifplugin.API
	nsPlugin          nsplugin.API
	addrAlloc         netalloc.AddressAllocator
	scheduler         kvs.KVScheduler

	// parallelization of the Retrieve operation
	goRoutinesCnt int
}

// NewPolicyRuleDescriptor creates a new instance of the policy descriptor.
func NewPolicyRuleDescriptor(
	scheduler kvs.KVScheduler, ifPlugin ifplugin.API, nsPlugin nsplugin.API, addrAlloc netalloc.AddressAllocator,
	policyRuleHandler srv6linuxcalls.PolicyRuleAPI, log logging.PluginLogger, goRoutinesCnt int) *kvs.KVDescriptor {

	ctx := &PolicyRuleDescriptor{
		scheduler:         scheduler,
		policyRuleHandler: policyRuleHandler,
		ifPlugin:          ifPlugin,
		nsPlugin:          nsPlugin,
		addrAlloc:         addrAlloc,
		goRoutinesCnt:     goRoutinesCnt,
		log:               log.NewLogger("policy-rule-descriptor"),
	}

	typedDescr := &adapter.PolicyRuleDescriptor{
		Name:            PolicyRuleDescriptorName,
		NBKeyPrefix:     linux_srv6.ModelPolicyRule.KeyPrefix(),
		ValueTypeName:   linux_srv6.ModelPolicyRule.ProtoName(),
		KeySelector:     linux_srv6.ModelPolicyRule.IsKeyValid,
		KeyLabel:        linux_srv6.ModelPolicyRule.StripKeyPrefix,
		ValueComparator: ctx.EquivalentPolicies,
		Validate:        ctx.Validate,
		Create:          ctx.Create,
		Delete:          ctx.Delete,
		Update:          ctx.Update,
		RetrieveDependencies: []string{
			netalloc_descr.IPAllocDescriptorName,
			ifdescriptor.InterfaceDescriptorName},
	}
	return adapter.NewPolicyRuleDescriptor(typedDescr)
}

func (d *PolicyRuleDescriptor) EquivalentPolicies(key string, oldPolicyRule, NewPolicyRule *linux_srv6.PolicyRule) bool {
	// compare sid case-insensitively
	return strings.ToLower(oldPolicyRule.Prefix) == strings.ToLower(oldPolicyRule.Prefix) &&
		oldPolicyRule.TableId == oldPolicyRule.TableId
}

// Validate validates policy rule configuration.
func (d *PolicyRuleDescriptor) Validate(key string, policyRule *linux_srv6.PolicyRule) (err error) {
	if policyRule.Prefix == "" {
		return kvs.NewInvalidValueError(ErrPolicyRuleWithoutPrefix, "prefix")
	}
	if policyRule.TableId < 0 || policyRule.TableId > 255 {
		return kvs.NewInvalidValueError(ErrPolicyRuleWithoutTableId, "table id")
	}

	return nil
}

// Create creates policy rule entry.
func (d *PolicyRuleDescriptor) Create(key string, policyRule *linux_srv6.PolicyRule) (metadata interface{}, err error) {
	//err = d.updatePolicyRule(policyRule, "add", d.policyRuleHandler.AddRule)
	//return nil, err
	output, err := d.policyRuleHandler.SetPolicyRuleCommand(cncpexec.ActionAdd, policyRule)
	d.log.Info(output)
	return nil, err
}

// Delete removes policy rule entry.
func (d *PolicyRuleDescriptor) Delete(key string, policyRule *linux_srv6.PolicyRule, metadata interface{}) error {
	//return d.updatePolicyRule(policyRule, "delete", d.policyRuleHandler.DelRule)
	output, err := d.policyRuleHandler.SetPolicyRuleCommand(cncpexec.ActionDelete, policyRule)
	d.log.Info(output)
	return err
}

func (d *PolicyRuleDescriptor) Update(key string, oldPolicyRule, newPolicyRule *linux_srv6.PolicyRule,
	oldMetadata interface{}) (newMetadata interface{}, err error) {
	//err = d.updatePolicyRule(newPolicyRule, "modify", d.policyRuleHandler.ReplaceRule)
	//return nil, err

	output, err := d.policyRuleHandler.SetPolicyRuleCommand(cncpexec.ActionDelete, oldPolicyRule)
	if err != nil {
		return nil, err
	}
	output, err = d.policyRuleHandler.SetPolicyRuleCommand(cncpexec.ActionAdd, newPolicyRule)
	if err != nil {
		return nil, err
	}
	d.log.Info(output)
	return nil, err
}

// updatePolicy adds, modifies or deletes a policy rule entry.
func (d *PolicyRuleDescriptor) updatePolicyRule(policyRule *linux_srv6.PolicyRule,
	actionName string, actionClb func(policyRuleEntry *netlink.Rule) error) error {
	var err error

	// Prepare policy entry object
	netlinkRule := &netlink.Rule{}

	netlinkRule.Table = int(policyRule.TableId)
	_, ipNet, err := net.ParseCIDR(policyRule.Prefix)
	if err != nil {
		d.log.Error(err)
		return err
	}
	netlinkRule.Dst = ipNet

	// update route in the interface namespace
	err = actionClb(netlinkRule)
	if err != nil {
		err = errors.Errorf("failed to %s linux policy rule: %v", actionName, err)
		d.log.Error(err)
		return err
	}

	return nil
}
