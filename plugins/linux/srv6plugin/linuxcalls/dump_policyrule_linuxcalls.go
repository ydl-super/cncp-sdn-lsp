package linuxcalls

import (
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"

	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/linux/nsplugin/linuxcalls"
	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
)

// retrievedRules is used as the return value sent via channel by retrieveRules().
type retrievedPolicyRules struct {
	policyRules []*PolicyRuleDetails
	err         error
}

// GetPolicyRules reads all configured static rules with the given outgoing
// interface.
// <interfaceIdx> works as filter, if set to zero, all rules in the namespace
// are returned.
func (h *NetLinkHandler) GetPolicyRules(table int) (v4Rules, v6Rules []netlink.Rule, err error) {
	var ruleFilter *netlink.Rule
	var filterMask uint64
	if table != 0 {
		ruleFilter = &netlink.Rule{
			Table: table,
		}
		if table != 0 {
			filterMask |= netlink.RT_FILTER_TABLE
		}
	}
	v4Rules, err = netlink.RuleListFiltered(netlink.FAMILY_V4, ruleFilter, filterMask)
	if err != nil {
		return
	}
	v6Rules, err = netlink.RuleListFiltered(netlink.FAMILY_V6, ruleFilter, filterMask)
	return
}

// DumpPolicyRules reads all policy rule entries and returns them as details
// with proto-modeled rule data and additional metadata
func (h *NetLinkHandler) DumpPolicyRules() ([]*PolicyRuleDetails, error) {
	interfaces := h.ifIndexes.ListAllInterfaces()
	goRoutinesCnt := len(interfaces) / minWorkForGoRoutine
	if goRoutinesCnt == 0 {
		goRoutinesCnt = 1
	}
	if goRoutinesCnt > h.goRoutineCount {
		goRoutinesCnt = h.goRoutineCount
	}
	ch := make(chan retrievedPolicyRules, goRoutinesCnt)

	// invoke multiple go routines for more efficient parallel rule retrieval
	for idx := 0; idx < goRoutinesCnt; idx++ {
		if goRoutinesCnt > 1 {
			go h.retrievePolicyRules(interfaces, idx, goRoutinesCnt, ch)
		} else {
			h.retrievePolicyRules(interfaces, idx, goRoutinesCnt, ch)
		}
	}

	// collect results from the go routines
	var policyRuleDetails []*PolicyRuleDetails
	for idx := 0; idx < goRoutinesCnt; idx++ {
		retrieved := <-ch
		if retrieved.err != nil {
			return nil, retrieved.err
		}
		// correlate with the expected configuration
		policyRuleDetails = append(policyRuleDetails, retrieved.policyRules...)
	}

	return policyRuleDetails, nil
}

// retrievePolicyRules is run by a separate go routine to retrieve all policies entries
// associated with every <goRoutineIdx>-th interface.
func (h *NetLinkHandler) retrievePolicyRules(interfaces []string, goRoutineIdx, goRoutinesCnt int, ch chan<- retrievedPolicyRules) {
	var retrieved retrievedPolicyRules
	nsCtx := linuxcalls.NewNamespaceMgmtCtx()

	for i := goRoutineIdx; i < len(interfaces); i += goRoutinesCnt {
		ifName := interfaces[i]
		// get interface metadata
		ifMeta, found := h.ifIndexes.LookupByName(ifName)
		if !found || ifMeta == nil {
			retrieved.err = errors.Errorf("failed to obtain metadata for interface %s", ifName)
			h.log.Error(retrieved.err)
			break
		}

		// obtain the associated routing table
		var table int
		if ifMeta.VrfMasterIf != "" {
			vrfMeta, found := h.ifIndexes.LookupByName(ifMeta.VrfMasterIf)
			if found {
				table = int(vrfMeta.VrfDevRT)
			}
		}

		// switch to the namespace of the interface
		revertNs, err := h.nsPlugin.SwitchToNamespace(nsCtx, ifMeta.Namespace)
		if err != nil {
			// namespace and all the rules it had contained no longer exist
			h.log.WithFields(logging.Fields{
				"err":       err,
				"namespace": ifMeta.Namespace,
			}).Warn("Failed to retrieve rules from the namespace")
			continue
		}

		// get Rules assigned to this interface
		v4Rules, v6Rules, err := h.GetPolicyRules(table)
		revertNs()
		if err != nil {
			retrieved.err = err
			h.log.Error(retrieved.err)
			break
		}

		// convert each rule from Netlink representation to the NB representation
		ipNet, err := netlink.ParseIPNet("::/0")
		if err != nil {
			retrieved.err = err
			h.log.Error(retrieved.err)
			break
		}
		for _, rule := range append(v4Rules, v6Rules...) {
			retrieved.policyRules = append(retrieved.policyRules, &PolicyRuleDetails{
				PolicyRule: &linux_srv6.PolicyRule{
					Prefix:  rule.Dst.String(),
					TableId: uint32(rule.Table),
				},
				Meta: &RuleMeta{
					Family: unix.AF_INET6,
					Src:    ipNet,
				},
			})
		}
	}

	ch <- retrieved
}
