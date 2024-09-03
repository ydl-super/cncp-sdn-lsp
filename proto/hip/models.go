package openhip_hip

import (
	"go.ligato.io/vpp-agent/v3/pkg/models"
)

// ModuleName is the name of the module used for models.
const ModuleName = "openhip.hip"

var (
	ModelHip = models.Register(&HipCMD{}, models.Spec{
		Module:  ModuleName,
		Version: "v1",
		Type:    "hip",
	})

	ModelHitgen = models.Register(&HitgenCMD{}, models.Spec{
		Module:  ModuleName,
		Version: "v1",
		Type:    "hitgen",
	})
)
