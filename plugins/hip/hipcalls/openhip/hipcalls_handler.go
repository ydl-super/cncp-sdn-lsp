package openhip

import (
	"go.pantheon.tech/stonework/plugins/hip/hipcalls"
)

type HipHandler struct {
	isInit bool
}

func NewHipHandler() hipcalls.HipOpenhipAPI {
	return &HipHandler{
		isInit: false,
	}
}
