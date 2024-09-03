package linuxcalls

import (
	"strconv"

	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
	cncpexec "go.pantheon.tech/stonework/utils/exec"
)

type BlackHoleRouteHandler struct {
}

func NewBlackHoleRouteHandler() *BlackHoleRouteHandler {
	return &BlackHoleRouteHandler{}
}

type BlackHoleRouteAPI interface {
	SetBlackHoleRouteCommand(actionName string, blackHoleRoute *linux_srv6.BlackHoleRoute) (string, error)
}

func (h *BlackHoleRouteHandler) SetBlackHoleRouteCommand(actionName string, blackHoleRoute *linux_srv6.BlackHoleRoute) (string, error) {
	var params []string

	tableId := strconv.FormatUint(uint64(blackHoleRoute.TableId), 10)
	params = append(params, "-6", "route", actionName, "blackhole", "default", "table", tableId)
	output, err := cncpexec.ExecuteCommandInDirectory(cncpexec.DefaultExecutableFilePath, "ip", params)

	return output, err
}
