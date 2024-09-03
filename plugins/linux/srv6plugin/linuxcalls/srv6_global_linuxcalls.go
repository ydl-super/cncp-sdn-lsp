package linuxcalls

import (
	"os/exec"

	"github.com/go-errors/errors"

	linux_srv6 "go.pantheon.tech/stonework/proto/linux/srv6"
)

type SRv6GlobalHandler struct {
}

func NewSRv6GlobalHandler() *SRv6GlobalHandler {
	return &SRv6GlobalHandler{}
}

type SRv6GlobalAPI interface {
	SetSRv6GlobalCommand(srv6Global *linux_srv6.SRv6Global) (string, error)
}

func (h *SRv6GlobalHandler) SetSRv6GlobalCommand(srv6Global *linux_srv6.SRv6Global) (string, error) {
	var cmd *exec.Cmd
	var err error

	switch srv6Global.Type {
	case "tunsrc":
		if srv6Global.Address == "" {
			err = errors.Errorf("Linux srv6 global defined without address reference %s", srv6Global.Address)
			return "", err
		}
		//cmd = exec.Command("ip sr tunsrc set %s", srv6Global.Address)
		cmd = exec.Command("ip", "sr", "tunsrc", "set", srv6Global.Address)
	case "hmac":
		if srv6Global.KeyId == "" {
			err = errors.Errorf("Linux srv6 global defined without key id reference %s", srv6Global.KeyId)
			return "", err
		}
		if srv6Global.Algorithm == "" {
			err = errors.Errorf("Linux srv6 global defined without algorithm reference %s", srv6Global.Algorithm)
			return "", err
		}
		//cmd = exec.Command("ip sr hmac set  %s %s", srv6Global.KeyId, srv6Global.Algorithm)
		cmd = exec.Command("ip", "sr", "hmac", "set", srv6Global.KeyId, srv6Global.Algorithm)
	default:
		err = errors.Errorf("unknown srv6 set type %s", srv6Global.Type)
		return "", err

	}

	cmd.Dir = "/usr/local/sbin/"
	bytes, err := cmd.CombinedOutput()

	return string(bytes), err
}
