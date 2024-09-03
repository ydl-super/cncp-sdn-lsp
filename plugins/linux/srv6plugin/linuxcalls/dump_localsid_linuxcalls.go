package linuxcalls

import (
	"github.com/pkg/errors"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"

	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/linux/nsplugin/linuxcalls"
	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
)

const (
	// IP addresses matching any destination.
	IPv4AddrAny = "0.0.0.0"
	IPv6AddrAny = "::"

	// minimum number of interfaces to be given to a single Go routine for processing
	// in the Retrieve operation
	minWorkForGoRoutine = 3
)

// retrievedRoutes is used as the return value sent via channel by retrieveRoutes().
type retrievedRoutes struct {
	routes []*RouteDetails
	err    error
}

// GetRoutes reads all configured static routes with the given outgoing
// interface.
// <interfaceIdx> works as filter, if set to zero, all routes in the namespace
// are returned.
func (h *NetLinkHandler) GetRoutes(interfaceIdx, table int) (v4Routes, v6Routes []netlink.Route, err error) {
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

// DumpRoutes reads all route entries and returns them as details
// with proto-modeled route data and additional metadata
func (h *NetLinkHandler) DumpRoutes() ([]*RouteDetails, error) {
	interfaces := h.ifIndexes.ListAllInterfaces()
	goRoutinesCnt := len(interfaces) / minWorkForGoRoutine
	if goRoutinesCnt == 0 {
		goRoutinesCnt = 1
	}
	if goRoutinesCnt > h.goRoutineCount {
		goRoutinesCnt = h.goRoutineCount
	}
	ch := make(chan retrievedRoutes, goRoutinesCnt)

	// invoke multiple go routines for more efficient parallel route retrieval
	for idx := 0; idx < goRoutinesCnt; idx++ {
		if goRoutinesCnt > 1 {
			go h.retrieveRoutes(interfaces, idx, goRoutinesCnt, ch)
		} else {
			h.retrieveRoutes(interfaces, idx, goRoutinesCnt, ch)
		}
	}

	// collect results from the go routines
	var routeDetails []*RouteDetails
	for idx := 0; idx < goRoutinesCnt; idx++ {
		retrieved := <-ch
		if retrieved.err != nil {
			return nil, retrieved.err
		}
		// correlate with the expected configuration
		routeDetails = append(routeDetails, retrieved.routes...)
	}

	return routeDetails, nil
}

// retrieveRoutes is run by a separate go routine to retrieve all routes entries
// associated with every <goRoutineIdx>-th interface.
func (h *NetLinkHandler) retrieveRoutes(interfaces []string, goRoutineIdx, goRoutinesCnt int, ch chan<- retrievedRoutes) {
	var retrieved retrievedRoutes
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
		_, v6Routes, err := h.GetRoutes(ifMeta.LinuxIfIndex, table)
		revertNs()
		if err != nil {
			retrieved.err = err
			h.log.Error(retrieved.err)
			break
		}

		// convert each route from Netlink representation to the NB representation
		for idx, route := range v6Routes {
			if route.Encap != nil {
				switch route.Encap.(type) {
				case *netlink.SEG6LocalEncap:
					var sid string
					sid = route.Dst.String()
					seg6LocalEncap := route.Encap.(*netlink.SEG6LocalEncap)
					//sid = seg6LocalEncap.Segments[0].String()
					retrieved.routes = append(retrieved.routes, &RouteDetails{
						Route: &linux_srv6.LocalSID{
							Sid:    sid,
							Device: ifName,
						},
						Meta: &RouteMeta{
							InterfaceIndex: uint32(route.LinkIndex),
							NetlinkScope:   route.Scope,
							Protocol:       uint32(route.Protocol),
							MTU:            uint32(route.MTU),
							Table:          uint32(route.Table),
						},
					})
					switch seg6LocalEncap.Action {
					case nl.SEG6_LOCAL_ACTION_END:
					case nl.SEG6_LOCAL_ACTION_END_X:
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionX).EndFunctionX.NextHop =
							route.Encap.(*netlink.SEG6LocalEncap).InAddr.String()
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionX).EndFunctionX.NextHop =
							route.Encap.(*netlink.SEG6LocalEncap).In6Addr.String()
					case nl.SEG6_LOCAL_ACTION_END_T:
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionT).EndFunctionT.VrfId =
							uint32(route.Encap.(*netlink.SEG6LocalEncap).Table)
					case nl.SEG6_LOCAL_ACTION_END_DX2:
						// TODO: Add params to seg6LocalEncap
					case nl.SEG6_LOCAL_ACTION_END_DX4:
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx4).EndFunctionDx4.NextHop =
							route.Encap.(*netlink.SEG6LocalEncap).InAddr.String()
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx4).EndFunctionDx4.NextHop =
							route.Encap.(*netlink.SEG6LocalEncap).In6Addr.String()
					case nl.SEG6_LOCAL_ACTION_END_DX6:
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx6).EndFunctionDx6.NextHop =
							route.Encap.(*netlink.SEG6LocalEncap).InAddr.String()
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx6).EndFunctionDx6.NextHop =
							route.Encap.(*netlink.SEG6LocalEncap).In6Addr.String()
					case nl.SEG6_LOCAL_ACTION_END_DT4:
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionDt4).EndFunctionDt4.VrfId =
							uint32(route.Encap.(*netlink.SEG6LocalEncap).Table)
					case nl.SEG6_LOCAL_ACTION_END_DT6:
						retrieved.routes[idx].Route.EndFunction.(*linux_srv6.LocalSID_EndFunctionDt6).EndFunctionDt6.VrfId =
							uint32(route.Encap.(*netlink.SEG6LocalEncap).Table)
					default:
						retrieved.err = errors.Errorf("failed to obtain action for seg6LocalEncap %d", seg6LocalEncap.Action)
						h.log.Error(retrieved.err)
						return
					}
				}

			}
		}
	}

	ch <- retrieved
}
