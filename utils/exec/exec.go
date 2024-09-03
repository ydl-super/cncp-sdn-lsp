package exec

import (
	"fmt"
	"os/exec"

	log "go.ligato.io/cn-infra/v2/logging"
)

const (
	DefaultExecutableFilePath = "/usr/local/sbin/"

	ActionAdd    = "add"
	ActionDelete = "del"
)

func ExecuteCommandInDirectory(dir string, commandName string, params []string) (string, error) {
	var paramStr string

	cmd := exec.Command(commandName, params...)
	cmd.Dir = dir
	for _, param := range params {
		paramStr = fmt.Sprintf("%s %s", paramStr, param)
	}
	log.Info(fmt.Sprintf("%s %s %s", dir, commandName, paramStr))
	bytes, err := cmd.CombinedOutput()
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
