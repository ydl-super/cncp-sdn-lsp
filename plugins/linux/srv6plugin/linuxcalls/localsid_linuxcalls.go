package linuxcalls

import (
	"github.com/go-errors/errors"
	"strconv"

	log "go.ligato.io/cn-infra/v2/logging"

	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
	cncpexec "go.pantheon.tech/stonework/utils/exec"
)

// for netlink
//// AddRoute creates the new static route
//func (h *NetLinkHandler) AddRoute(route *netlink.Route) error {
//	return netlink.RouteAdd(route)
//}
//
//// ReplaceRoute replaces the static route
//func (h *NetLinkHandler) ReplaceRoute(route *netlink.Route) error {
//	return netlink.RouteReplace(route)
//}
//
//// DelRoute removes the static route
//func (h *NetLinkHandler) DelRoute(route *netlink.Route) error {
//	return netlink.RouteDel(route)
//}

type LocalSIDHandler struct {
}

func NewLocalSIDHandler() *LocalSIDHandler {
	return &LocalSIDHandler{}
}

type LocalSIDAPI interface {
	SetLocalSIDCommand(actionName string, localSID *linux_srv6.LocalSID) (string, error)
}

func (h *LocalSIDHandler) SetLocalSIDCommand(actionName string, localSID *linux_srv6.LocalSID) (string, error) {
	var params []string

	params = append(params, "-6", "route", actionName, localSID.Sid, "encap", "seg6local", "action")
	switch localSID.EndFunction.(type) {
	case *linux_srv6.LocalSID_BaseEndFunction:
		params = append(params, "End")
	case *linux_srv6.LocalSID_EndFunctionX:
		params = append(params, "End.X", "nh6", localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionX).EndFunctionX.NextHop)
	case *linux_srv6.LocalSID_EndFunctionT:
		params = append(params, "End.T", "table", strconv.Itoa(int(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionT).EndFunctionT.VrfId)))
	case *linux_srv6.LocalSID_EndFunctionDx2:
		params = append(params, "End.DX2", "oif", localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx2).EndFunctionDx2.OutgoingInterface)
	case *linux_srv6.LocalSID_EndFunctionDx4:
		params = append(params, "End.DX4", "nh4", localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx4).EndFunctionDx4.NextHop)
	case *linux_srv6.LocalSID_EndFunctionDx6:
		params = append(params, "End.DX6", "nh6", localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDx6).EndFunctionDx6.NextHop)
	case *linux_srv6.LocalSID_EndFunctionDt4:
		params = append(params, "End.DT4", "table", strconv.Itoa(int(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDt4).EndFunctionDt4.VrfId)))
	case *linux_srv6.LocalSID_EndFunctionDt6:
		params = append(params, "End.DT6", "table", strconv.Itoa(int(localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionDt6).EndFunctionDt6.VrfId)))
	case *linux_srv6.LocalSID_EndFunctionB6:
		var segments string
		var keyId = localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionB6).EndFunctionB6.KeyId
		var segmentArr = localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionB6).EndFunctionB6.Segments
		for i := 0; i < len(segmentArr); i++ {
			segments += segmentArr[i]
			if i < len(segmentArr)-1 {
				segments += ","
			}
		}
		params = append(params, "End.B6", "srh", "segs", segments)
		if keyId != "" {
			params = append(params, "hmac", keyId)
		}
	case *linux_srv6.LocalSID_EndFunctionB6Encaps:
		var segments string
		var keyId = localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionB6Encaps).EndFunctionB6Encaps.KeyId
		var segmentArr = localSID.EndFunction.(*linux_srv6.LocalSID_EndFunctionB6Encaps).EndFunctionB6Encaps.Segments
		for i := 0; i < len(segmentArr); i++ {
			segments += segmentArr[i]
			if i < len(segmentArr)-1 {
				segments += ","
			}
		}
		params = append(params, "End.B6.Encaps", "srh", "segs", segments)
		if keyId != "" {
			params = append(params, "hmac", keyId)
		}
	default:
		return "", errors.Errorf("unsupported end function %v", localSID.EndFunction)
	}
	params = append(params, "dev", localSID.Device)
	output, err := cncpexec.ExecuteCommandInDirectory(cncpexec.DefaultExecutableFilePath, "ip", params)
	if err != nil {
		return "", err
	}
	log.Info(output)

	return output, nil
}
