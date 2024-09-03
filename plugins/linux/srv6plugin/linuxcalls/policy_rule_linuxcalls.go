package linuxcalls

import (
	"strconv"

	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
	cncpexec "go.pantheon.tech/stonework/utils/exec"
)

//// AddRule creates the new rule
//func (h *NetLinkHandler) AddRule(rule *netlink.Rule) error {
//	return netlink.RuleAdd(rule)
//}
//
//// ReplaceRule replaces the rule
//func (h *NetLinkHandler) ReplaceRule(rule *netlink.Rule) error {
//	return netlink.RuleAdd(rule)
//}
//
//// DelRule removes the rule
//func (h *NetLinkHandler) DelRule(rule *netlink.Rule) error {
//	return netlink.RuleAdd(rule)
//}

type PolicyRuleHandler struct {
}

func NewPolicyRuleHandler() *PolicyRuleHandler {
	return &PolicyRuleHandler{}
}

type PolicyRuleAPI interface {
	SetPolicyRuleCommand(actionName string, policyRule *linux_srv6.PolicyRule) (string, error)
}

func (h *PolicyRuleHandler) SetPolicyRuleCommand(actionName string, policyRule *linux_srv6.PolicyRule) (string, error) {
	var params []string

	tableId := strconv.FormatUint(uint64(policyRule.TableId), 10)
	params = append(params, "-6", "rule", actionName, "to", policyRule.Prefix, "lookup", tableId)
	output, err := cncpexec.ExecuteCommandInDirectory(cncpexec.DefaultExecutableFilePath, "ip", params)

	return output, err
}
