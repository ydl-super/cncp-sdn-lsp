// Copyright (c) 2018 Cisco and/or its affiliates.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at:
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:generate descriptor-adapter --descriptor-name LocalSID --value-type *linux_srv6.LocalSID --import "go.pantheon.tech/stonework/proto/linux/srv6" --output-dir "descriptor"
//go:generate descriptor-adapter --descriptor-name Policy --value-type *linux_srv6.Policy --import "go.pantheon.tech/stonework/proto/linux/srv6" --output-dir "descriptor"
//go:generate descriptor-adapter --descriptor-name PolicyRule --value-type *linux_srv6.PolicyRule --import "go.pantheon.tech/stonework/proto/linux/srv6" --output-dir "descriptor"
//go:generate descriptor-adapter --descriptor-name BlackHoleRoute --value-type *linux_srv6.BlackHoleRoute --import "go.pantheon.tech/stonework/proto/linux/srv6" --output-dir "descriptor"
//go:generate descriptor-adapter --descriptor-name SRv6Global --value-type *linux_srv6.SRv6Global --import "go.pantheon.tech/stonework/proto/linux/srv6" --output-dir "descriptor"

package srv6plugin

import (
	"go.ligato.io/cn-infra/v2/infra"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.ligato.io/vpp-agent/v3/plugins/linux/ifplugin"
	"go.ligato.io/vpp-agent/v3/plugins/linux/nsplugin"
	"go.ligato.io/vpp-agent/v3/plugins/netalloc"

	"go.pantheon.tech/stonework/plugins/linux/srv6plugin/descriptor"
	"go.pantheon.tech/stonework/plugins/linux/srv6plugin/linuxcalls"
)

const (
	// by default, at most 10 go routines will split the configured namespaces
	// to execute the Retrieve operation in parallel.
	defaultGoRoutinesCnt = 10
)

// SRv6Plugin configures Linux routes and ARP entries using Netlink API.
type SRv6Plugin struct {
	Deps

	// From configuration file
	disabled bool

	// system handlers
	srv6Handler           linuxcalls.NetlinkAPI
	srv6GlobalHandler     linuxcalls.SRv6GlobalAPI
	localsidHandler       linuxcalls.LocalSIDAPI
	policyHandler         linuxcalls.PolicyAPI
	blackHoleRouteHandler linuxcalls.BlackHoleRouteAPI
	policyRuleHandler     linuxcalls.PolicyRuleAPI

	// descriptors
	//localsidDescriptor       *descriptor.LocalSIDDescriptor
	//policyDescriptor         *descriptor.PolicyDescriptor
	//blackHoleRouteDescriptor *descriptor.BlackHoleRouteDescriptor
	//policyRuleDescriptor     *descriptor.PolicyRuleDescriptor
}

// Deps lists dependencies of the interface p.
type Deps struct {
	infra.PluginDeps
	KVScheduler kvs.KVScheduler
	NsPlugin    nsplugin.API
	IfPlugin    ifplugin.API
	AddrAlloc   netalloc.AddressAllocator
}

// Config holds the srv6 plugin configuration.
type Config struct {
	Disabled      bool `json:"disabled"`
	GoRoutinesCnt int  `json:"go-routines-count"`
}

// Init initializes and registers descriptors for Linux LocalSIDs.
func (p *SRv6Plugin) Init() error {
	// parse configuration file
	config, err := p.retrieveConfig()
	if err != nil {
		return err
	}
	p.Log.Debugf("Linux SRv6 plugin config: %+v", config)
	if config.Disabled {
		p.disabled = true
		p.Log.Infof("Disabling Linux SRv6 plugin")
		return nil
	}

	// init handlers
	//p.srv6Handler = linuxcalls.NewNetLinkHandler(p.NsPlugin, p.IfPlugin.GetInterfaceIndex(), defaultGoRoutinesCnt, p.Log)
	//p.srv6GlobalHandler = linuxcalls.NewSRv6GlobalHandler()

	//localSIDDescriptor := descriptor.NewLocalSIDDescriptor(
	//	p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.srv6Handler, p.Log, config.GoRoutinesCnt)
	//err = p.Deps.KVScheduler.RegisterKVDescriptor(localSIDDescriptor)
	//if err != nil {
	//	return err
	//}
	//
	//policyDescriptor := descriptor.NewPolicyDescriptor(
	//	p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.srv6Handler, p.Log, config.GoRoutinesCnt)
	//err = p.Deps.KVScheduler.RegisterKVDescriptor(policyDescriptor)
	//if err != nil {
	//	return err
	//}
	//
	//policyRuleDescriptor := descriptor.NewPolicyRuleDescriptor(
	//	p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.srv6Handler, p.Log, config.GoRoutinesCnt)
	//err = p.Deps.KVScheduler.RegisterKVDescriptor(policyRuleDescriptor)
	//if err != nil {
	//	return err
	//}
	//
	//blackholeRouteDescriptor := descriptor.NewBlackHoleRouteDescriptor(
	//	p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.srv6Handler, p.Log, config.GoRoutinesCnt)
	//err = p.Deps.KVScheduler.RegisterKVDescriptor(blackholeRouteDescriptor)
	//if err != nil {
	//	return err
	//}

	p.srv6GlobalHandler = linuxcalls.NewSRv6GlobalHandler()
	srv6GlobalDescriptor := descriptor.NewSRv6GlobalDescriptor(
		p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.srv6GlobalHandler, p.Log, config.GoRoutinesCnt)
	err = p.Deps.KVScheduler.RegisterKVDescriptor(srv6GlobalDescriptor)
	if err != nil {
		return err
	}

	p.localsidHandler = linuxcalls.NewLocalSIDHandler()
	localsidDescriptor := descriptor.NewLocalSIDDescriptor(
		p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.localsidHandler, p.Log, config.GoRoutinesCnt)
	err = p.Deps.KVScheduler.RegisterKVDescriptor(localsidDescriptor)
	if err != nil {
		return err
	}

	p.policyHandler = linuxcalls.NewPolicyHandler()
	policyDescriptor := descriptor.NewPolicyDescriptor(
		p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.policyHandler, p.Log, config.GoRoutinesCnt)
	err = p.Deps.KVScheduler.RegisterKVDescriptor(policyDescriptor)
	if err != nil {
		return err
	}

	p.policyRuleHandler = linuxcalls.NewPolicyRuleHandler()
	policyRuleDescriptor := descriptor.NewPolicyRuleDescriptor(
		p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.policyRuleHandler, p.Log, config.GoRoutinesCnt)
	err = p.Deps.KVScheduler.RegisterKVDescriptor(policyRuleDescriptor)
	if err != nil {
		return err
	}

	p.blackHoleRouteHandler = linuxcalls.NewBlackHoleRouteHandler()
	blackHoleRouteDescriptor := descriptor.NewBlackHoleRouteDescriptor(
		p.KVScheduler, p.IfPlugin, p.NsPlugin, p.AddrAlloc, p.blackHoleRouteHandler, p.Log, config.GoRoutinesCnt)
	err = p.Deps.KVScheduler.RegisterKVDescriptor(blackHoleRouteDescriptor)
	if err != nil {
		return err
	}

	return nil
}

// Close does nothing here.
func (p *SRv6Plugin) Close() error {
	return nil
}

// retrieveConfig loads L3Plugin configuration file.
func (p *SRv6Plugin) retrieveConfig() (*Config, error) {
	config := &Config{
		// default configuration
		GoRoutinesCnt: defaultGoRoutinesCnt,
	}
	found, err := p.Cfg.LoadValue(config)
	if !found {
		p.Log.Debug("Linux SRV6Plugin config not found")
		return config, nil
	}
	if err != nil {
		return nil, err
	}
	return config, err
}
