package linux_srv6

import (
	"strings"

	"go.ligato.io/vpp-agent/v3/pkg/models"
)

// ModuleName is the name of the module used for models.
const ModuleName = "linux.srv6"

var (
	ModelLocalSID = models.Register(&LocalSID{}, models.Spec{
		Module:  ModuleName,
		Type:    "localsid",
		Version: "v1",
	}, models.WithNameTemplate(`{{with ipnet .Sid}}{{printf "%s/%d" .IP .MaskSize}}`+
		`{{else}}{{.Sid}}{{end}}/{{.Device}}`,
	))

	ModelPolicy = models.Register(&Policy{}, models.Spec{
		Module:  ModuleName,
		Type:    "policy",
		Version: "v1",
	}, models.WithNameTemplate(`{{with ipnet .Prefix}}{{printf "%s/%d" .IP .MaskSize}}`+
		`{{else}}{{.Prefix}}{{end}}/{{.Device}}`,
	))

	ModelPolicyRule = models.Register(&PolicyRule{}, models.Spec{
		Module:  ModuleName,
		Type:    "policy_rule",
		Version: "v1",
	})

	ModelBlackHoleRoute = models.Register(&BlackHoleRoute{}, models.Spec{
		Module:  ModuleName,
		Type:    "blackhole_route",
		Version: "v1",
	})

	ModelSRv6Global = models.Register(&SRv6Global{}, models.Spec{
		Module:  ModuleName,
		Type:    "srv6global",
		Version: "v1",
	})
)

// LocalSIDKey returns the key used in ETCD to store configuration of a particular Linux LocalSIDKey.
func LocalSIDKey(sid, device string) string {
	return models.Key(&LocalSID{
		Sid:    sid,
		Device: device,
	})
}

// PolicyKey returns the key used in ETCD to store configuration of a particular Linux PolicyKey.
func PolicyKey(prefix, device string) string {
	return models.Key(&Policy{
		Prefix: prefix,
		Device: device,
	})
}

const (
	/* Link-local route (derived) */

	// StaticLinkLocalRouteKeyPrefix is a prefix for keys derived from link-local routes.
	LinkLocalRouteKeyPrefix = "linux/link-local-route/"

	// staticLinkLocalRouteKeyTemplate is a template for key derived from link-local route.
	linkLocalRouteKeyTemplate = LinkLocalRouteKeyPrefix + "{out-iface}/dest-address/{dest-address}"
)

/* Link-local Route (derived) */

// StaticLinkLocalSIDKey returns a derived key used to represent link-local route.
func StaticLinkLocalSIDKey(sid, device string) string {
	key := strings.Replace(linkLocalRouteKeyTemplate, "{dest-address}", sid, 1)
	key = strings.Replace(key, "{out-iface}", device, 1)
	return key
}

// StaticLinkLocalSIDPrefix returns longest-common prefix of keys representing
// link-local routes that have the given outgoing Linux interface.
func StaticLinkLocalSIDPrefix(device string) string {
	return LinkLocalRouteKeyPrefix + device + "/"
}

// ParseStaticLinkLocalSIDKey parses route attributes from a key derived from link-local route.
func ParseStaticLinkLocalSIDKey(key string) (sid string, device string, isRouteKey bool) {
	if strings.HasPrefix(key, LinkLocalRouteKeyPrefix) {
		routeSuffix := strings.TrimPrefix(key, LinkLocalRouteKeyPrefix)
		parts := strings.Split(routeSuffix, "/dest-address/")

		if len(parts) != 2 {
			return "", "", false
		}
		device = parts[0]
		sid = parts[1]
		isRouteKey = true
		return
	}
	return "", "", false
}

/* Link-local Route (derived) */

// StaticLinkPolicyKey (prefix, device string) string { returns a derived key used to represent link-local route.
func StaticLinkPolicyKey(prefix, device string) string {
	key := strings.Replace(linkLocalRouteKeyTemplate, "{dest-address}", prefix, 1)
	key = strings.Replace(key, "{out-iface}", device, 1)
	return key
}

// StaticLinkPolicyPrefix returns longest-common prefix of keys representing
// link-local routes that have the given outgoing Linux interface.
func StaticLinkPolicyPrefix(device string) string {
	return LinkLocalRouteKeyPrefix + device + "/"
}

// ParseStaticLinkPolicyKey parses route attributes from a key derived from link-local route.
func ParseStaticLinkPolicyKey(key string) (prefix string, device string, isRouteKey bool) {
	if strings.HasPrefix(key, LinkLocalRouteKeyPrefix) {
		routeSuffix := strings.TrimPrefix(key, LinkLocalRouteKeyPrefix)
		parts := strings.Split(routeSuffix, "/dest-address/")

		if len(parts) != 2 {
			return "", "", false
		}
		device = parts[0]
		prefix = parts[1]
		isRouteKey = true
		return
	}
	return "", "", false
}
