// SPDX-License-Identifier: Apache-2.0

// Copyright 2021 PANTHEON.tech
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:generate descriptor-adapter --descriptor-name Hip --value-type *openhip_hip.HipCMD --import "go.pantheon.tech/stonework/proto/hip" --output-dir "descriptor"
//go:generate descriptor-adapter --descriptor-name Hitgen --value-type *openhip_hip.HitgenCMD --import "go.pantheon.tech/stonework/proto/hip" --output-dir "descriptor"

package hipplugin

import (
	"github.com/go-errors/errors"
	"go.ligato.io/cn-infra/v2/infra"
	kvs "go.ligato.io/vpp-agent/v3/plugins/kvscheduler/api"
	"go.pantheon.tech/stonework/plugins/hip/descriptor"
	"go.pantheon.tech/stonework/plugins/hip/hipcalls"
	"go.pantheon.tech/stonework/plugins/hip/hipcalls/openhip"
)

type Hipv2Plugin struct {
	Deps

	// handlers
	hipHandler hipcalls.HipOpenhipAPI
}

// Deps lists dependencies of the hip plugin.
type Deps struct {
	infra.PluginDeps
	KVScheduler kvs.KVScheduler
}

//Init registers hip-related descriptors.
func (p *Hipv2Plugin) Init() (err error) {
	// init handlers
	p.hipHandler = openhip.NewHipHandler()
	if p.hipHandler == nil {
		return errors.New("hipHandler is not available")
	}
	hipDescriptor := descriptor.NewHipCommondDescriptor(p.hipHandler, p.Log)
	hitgenDescriptor := descriptor.NewHitgenCommondDescriptor(p.hipHandler, p.Log)
	if hipDescriptor == nil {
		p.Log.Info("hipDescriptor is not available")
	}
	if hitgenDescriptor == nil {
		p.Log.Info("hipDescriptor is not available")
	}
	err = p.KVScheduler.RegisterKVDescriptor(
		hipDescriptor,
		hitgenDescriptor,
	)
	if err != nil {
		p.Log.Info("error :%v", err)
		return err
	}
	p.Log.Info("hip plugin was initialized successfully")
	return nil
}
