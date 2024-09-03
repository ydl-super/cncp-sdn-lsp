package linuxcalls

import (
	"github.com/vishvananda/netlink"
	"net"

	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/linux/ifplugin/ifaceidx"
	"go.ligato.io/vpp-agent/v3/plugins/linux/nsplugin"
	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
)

// RouteDetails is an object combining linux route data based on proto
// model with additional metadata
type RouteDetails struct {
	Route *linux_srv6.LocalSID
	Meta  *RouteMeta
}

// PolicyDetails is an object combining linux route data based on proto
// model with additional metadata
type PolicyDetails struct {
	Policy *linux_srv6.Policy
	Meta   *RouteMeta
}

// BlackHoleRouteDetails is an object combining linux route data based on proto
// model with additional metadata
type BlackHoleRouteDetails struct {
	BlackHoleRoute *linux_srv6.BlackHoleRoute
	Meta           *RouteMeta
}

// PolicyRuleDetails is an object combining linux policy rule data based on proto
// model with additional metadata
type PolicyRuleDetails struct {
	PolicyRule *linux_srv6.PolicyRule
	Meta       *RuleMeta
}

// RouteMeta represents linux Route metadata
type RouteMeta struct {
	InterfaceIndex uint32        `json:"interface_index"`
	NetlinkScope   netlink.Scope `json:"link_scope"`
	Protocol       uint32        `json:"protocol"`
	MTU            uint32        `json:"mtu"`
	Table          uint32        `json:"table"`
}

type RuleMeta struct {
	Family int
	Src    *net.IPNet
}

// NetlinkAPI interface covers all methods inside linux calls package needed
// to manage linux ARP entries and routes.
type NetlinkAPI interface {
	NetlinkAPIWrite
	NetlinkAPIRead
}

// NetlinkAPIWrite interface covers write methods inside linux calls package
// needed to manage linux ARP entries and routes.
type NetlinkAPIWrite interface {
	/* Routes */
	// AddRoute adds new linux static route.
	AddRoute(route *netlink.Route) error
	// ReplaceRoute changes existing linux static route.
	ReplaceRoute(route *netlink.Route) error
	// DelRoute removes linux static route.
	DelRoute(route *netlink.Route) error

	/* Rules */
	// AddRule adds new linux rule.
	AddRule(rule *netlink.Rule) error
	// ReplaceRule changes existing linux rule.
	ReplaceRule(rule *netlink.Rule) error
	// DelRule removes linux rule.
	DelRule(rule *netlink.Rule) error
}

// NetlinkAPIRead interface covers read methods inside linux calls package
// needed to manage linux ARP entries and routes.
type NetlinkAPIRead interface {
	// GetRoutes reads all configured static routes inside the given table
	// and with the given outgoing interface.
	// <interfaceIdx> works as filter, if set to zero, all routes in the namespace
	// are returned.
	// Zero <table> represents the main routing table.
	GetRoutes(interfaceIdx, table int) (v4Routes, v6Routes []netlink.Route, err error)

	// DumpRoutes reads all route entries and returns them as details
	// with proto-modeled route data and additional metadata
	DumpRoutes() ([]*RouteDetails, error)

	GetPolicies(interfaceIdx, table int) (v4Routes, v6Routes []netlink.Route, err error)

	// DumpPolicies reads all policy entries and returns them as details
	// with proto-modeled route data and additional metadata
	DumpPolicies() ([]*PolicyDetails, error)

	GetBlackHoleRoutes(table int) (v4Routes, v6Routes []netlink.Route, err error)

	// DumpBlackHoleRoutes reads all blackhole route entries and returns them as details
	// with proto-modeled route data and additional metadata
	DumpBlackHoleRoutes() ([]*BlackHoleRouteDetails, error)

	GetPolicyRules(table int) (v4Rules, v6Rules []netlink.Rule, err error)

	// DumpPolicyRules reads all blackhole route entries and returns them as details
	// with proto-modeled route data and additional metadata
	DumpPolicyRules() ([]*PolicyRuleDetails, error)
}

// NetLinkHandler is accessor for Netlink methods.
type NetLinkHandler struct {
	nsPlugin  nsplugin.API
	ifIndexes ifaceidx.LinuxIfMetadataIndex

	// parallelization of the Retrieve operation
	goRoutineCount int

	log logging.Logger
}

// NewNetLinkHandler creates new instance of Netlink handler.
func NewNetLinkHandler(nsPlugin nsplugin.API, ifIndexes ifaceidx.LinuxIfMetadataIndex, goRoutineCount int,
	log logging.Logger) *NetLinkHandler {
	return &NetLinkHandler{
		nsPlugin:       nsPlugin,
		ifIndexes:      ifIndexes,
		goRoutineCount: goRoutineCount,
		log:            log,
	}
}
