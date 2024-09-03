package linuxcalls

import (
	"net"

	log "go.ligato.io/cn-infra/v2/logging"

	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
	cncpexec "go.pantheon.tech/stonework/utils/exec"
)

type PolicyHandler struct {
}

func NewPolicyHandler() *PolicyHandler {
	return &PolicyHandler{}
}

type PolicyAPI interface {
	SetPolicyCommand(actionName string, policy *linux_srv6.Policy) (string, error)
}

func (h *PolicyHandler) SetPolicyCommand(actionName string, policy *linux_srv6.Policy) (string, error) {
	var params []string
	var segments string

	for i := 0; i < len(policy.Segments); i++ {
		segments += policy.Segments[i]
		if i < len(policy.Segments)-1 {
			segments += ","
		}
	}

	cidr, _, err := net.ParseCIDR(policy.Prefix)
	if err != nil {
		log.Error(err)
		return "", err
	}
	if cidr.To4() == nil && cidr.To16() != nil {
		params = append(params, "-6", "route",
			actionName, policy.Prefix, "encap", "seg6", "mode", policy.EncapMode, "segs", segments)
	} else {
		params = append(params, "route",
			actionName, policy.Prefix, "encap", "seg6", "mode", policy.EncapMode, "segs", segments)
	}
	if policy.KeyId != "" {
		params = append(params, "hmac", policy.KeyId)
	}
	params = append(params, "dev", policy.Device)

	output, err := cncpexec.ExecuteCommandInDirectory(cncpexec.DefaultExecutableFilePath, "ip", params)
	if err != nil {
		log.Error(err)
		return "", err
	}

	return output, err
}
