package linuxcalls

import (
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/linux/nsplugin/linuxcalls"
	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
)

// retrievedRoutes is used as the return value sent via channel by retrieveRoutes().
type retrievedPolicies struct {
	policies []*PolicyDetails
	err      error
}

// GetPolicies reads all configured static routes with the given outgoing
// interface.
// <interfaceIdx> works as filter, if set to zero, all routes in the namespace
// are returned.
func (h *NetLinkHandler) GetPolicies(interfaceIdx, table int) (v4Routes, v6Routes []netlink.Route, err error) {
	var routeFilter *netlink.Route
	var filterMask uint64
	if interfaceIdx != 0 || table != 0 {
		routeFilter = &netlink.Route{
			LinkIndex: interfaceIdx,
			Table:     table,
		}
		if interfaceIdx != 0 {
			filterMask |= netlink.RT_FILTER_OIF
		}
		if table != 0 {
			filterMask |= netlink.RT_FILTER_TABLE
		}
	}
	v4Routes, err = netlink.RouteListFiltered(netlink.FAMILY_V4, routeFilter, filterMask)
	if err != nil {
		return
	}
	v6Routes, err = netlink.RouteListFiltered(netlink.FAMILY_V6, routeFilter, filterMask)
	return
}

// DumpPolicies reads all route entries and returns them as details
// with proto-modeled route data and additional metadata
func (h *NetLinkHandler) DumpPolicies() ([]*PolicyDetails, error) {
	interfaces := h.ifIndexes.ListAllInterfaces()
	goRoutinesCnt := len(interfaces) / minWorkForGoRoutine
	if goRoutinesCnt == 0 {
		goRoutinesCnt = 1
	}
	if goRoutinesCnt > h.goRoutineCount {
		goRoutinesCnt = h.goRoutineCount
	}
	ch := make(chan retrievedPolicies, goRoutinesCnt)

	// invoke multiple go routines for more efficient parallel route retrieval
	for idx := 0; idx < goRoutinesCnt; idx++ {
		if goRoutinesCnt > 1 {
			go h.retrievePolicies(interfaces, idx, goRoutinesCnt, ch)
		} else {
			h.retrievePolicies(interfaces, idx, goRoutinesCnt, ch)
		}
	}

	// collect results from the go routines
	var policyDetails []*PolicyDetails
	for idx := 0; idx < goRoutinesCnt; idx++ {
		retrieved := <-ch
		if retrieved.err != nil {
			return nil, retrieved.err
		}
		// correlate with the expected configuration
		policyDetails = append(policyDetails, retrieved.policies...)
	}

	return policyDetails, nil
}

// retrievePolicies is run by a separate go routine to retrieve all policies entries
// associated with every <goRoutineIdx>-th interface.
func (h *NetLinkHandler) retrievePolicies(interfaces []string, goRoutineIdx, goRoutinesCnt int, ch chan<- retrievedPolicies) {
	var retrieved retrievedPolicies
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
			// namespace and all the routes it had contained no longer exist
			h.log.WithFields(logging.Fields{
				"err":       err,
				"namespace": ifMeta.Namespace,
			}).Warn("Failed to retrieve routes from the namespace")
			continue
		}

		// get routes assigned to this interface
		v4Routes, v6Routes, err := h.GetPolicies(ifMeta.LinuxIfIndex, table)
		revertNs()
		if err != nil {
			retrieved.err = err
			h.log.Error(retrieved.err)
			break
		}

		// convert each route from Netlink representation to the NB representation
		for idx, route := range append(v4Routes, v6Routes...) {
			seg6Encap := route.Encap.(*netlink.SEG6Encap)
			var segments = make([]string, 0)
			for _, segment := range seg6Encap.Segments {
				segments = append(segments, segment.String())
			}
			retrieved.policies = append(retrieved.policies, &PolicyDetails{
				Policy: &linux_srv6.Policy{
					Prefix:   route.Dst.String(),
					Device:   ifName,
					Segments: segments,
				},
				Meta: &RouteMeta{
					InterfaceIndex: uint32(route.LinkIndex),
					NetlinkScope:   route.Scope,
					Protocol:       uint32(route.Protocol),
					MTU:            uint32(route.MTU),
					Table:          uint32(route.Table),
				},
			})
			if route.Encap.(*netlink.SEG6Encap).Mode == nl.SEG6_IPTUN_MODE_INLINE {
				retrieved.policies[idx].Policy.EncapMode = "inline"
			} else {
				retrieved.policies[idx].Policy.EncapMode = "encap"
			}
		}
	}

	ch <- retrieved
}
