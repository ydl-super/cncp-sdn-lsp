package hipcalls

import (
	"go.pantheon.tech/stonework/proto/hip"
)

// HipOpenhipAPI provides methods for managing openhip hip configuration.
type HipOpenhipAPI interface {
	SetHipCommond(hip *openhip_hip.HipCMD) error
	SetHitgenCommond(hitgen *openhip_hip.HitgenCMD) error
	CloseHip() error
}
