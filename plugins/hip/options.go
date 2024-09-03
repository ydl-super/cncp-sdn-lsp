package hipplugin

import (
	"go.ligato.io/cn-infra/v2/logging"
	"go.ligato.io/vpp-agent/v3/plugins/kvscheduler"
)

var DefaultPlugin = *NewPlugin()

func NewPlugin(opts ...Option) *Hipv2Plugin {
	p := &Hipv2Plugin{}
	p.PluginName = "openhip-hipplugin"
	p.KVScheduler = &kvscheduler.DefaultPlugin
	for _, o := range opts {
		o(p)
	}

	if p.Log == nil {
		p.Log = logging.ForPlugin(p.String())
	}

	return p
}

// Option is a function that can be used in NewPlugin to customize Plugin.
type Option func(*Hipv2Plugin)

// UseDeps returns Option that can inject custom dependencies.
func UseDeps(f func(*Deps)) Option {
	return func(p *Hipv2Plugin) {
		f(&p.Deps)
	}
}
