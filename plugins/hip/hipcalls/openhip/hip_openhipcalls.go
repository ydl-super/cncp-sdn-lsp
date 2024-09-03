package openhip

import (
	"bytes"
	"fmt"
	"go.pantheon.tech/stonework/proto/hip"
	"os"
	"os/exec"
	"strconv"
)

func (h HipHandler) SetHipCommond(hip *openhip_hip.HipCMD) error {
	//if !h.isInit {
	//	InitHip()
	//}
	dir := "/usr/local/sbin/"
	args := []string{}
	if hip != nil {
		if hip.IsDetail {
			args = append(args, "-v")
		}
		if hip.IsQuiet {
			args = append(args, "-q")
		}
		if hip.IsDeamon {
			args = append(args, "-d")
		}
		if hip.IsR1 {
			args = append(args, "-r1")
		}
		if hip.IsOpportunistic {
			args = append(args, "-o")
		}
		if hip.IsAllowAny {
			args = append(args, "-a")
		}
		if hip.ConfPath != "" {
			args = append(args, "-conf", hip.ConfPath)
		}
		if hip.IsPersissive {
			args = append(args, "-p")
		}
		if hip.IsNoRetransmit {
			args = append(args, "-nr")
		}
		if hip.TriggerAddress != "" {
			args = append(args, "-t", hip.TriggerAddress)
		}
		if hip.IsRvs {
			args = append(args, "-rvs")
		}
		if hip.IsMr {
			args = append(args, "-mr")
		}
		if hip.IsMh {
			args = append(args, "-mh")
		}
	} else {
		args = append(args, "-v")
	}

	output, err := CmdAndChangeDir(dir, "./hip", args)
	if err != nil {
		return err
	}
	if output != "" {
		return fmt.Errorf(output)
	}
	return nil
}
func (h HipHandler) CloseHip() error {
	//kill $(cat /var/run/hip.pid)
	args := []string{"$(cat /var/run/hip.pid)"}
	output, err := CmdAndChangeDir("", "kill", args)
	if err != nil {
		return err
	}
	if output != "" {
		return fmt.Errorf(output)
	}
	return nil
}

func (h HipHandler) SetHitgenCommond(hitgen *openhip_hip.HitgenCMD) error {
	//if !h.isInit {
	//	InitHip()
	//}
	dir := "/usr/local/sbin/"
	args := []string{}
	if hitgen != nil {
		if hitgen.IsDetail {
			args = append(args, "-v")
		}
		if hitgen.Basename != "" {
			args = append(args, "-name", hitgen.Basename)
		}
		switch hitgen.Encryption {
		case 0:
			args = append(args, "-type", "DSA")
			break
		case 1:
			args = append(args, "-type", "RSA")
			break
		case 2:
			args = append(args, "-type", "ECDSA")
			break
		case 3:
			args = append(args, "-type", "AdDSA")
			break
		default:
			return fmt.Errorf("illegal encryption type: %v", hitgen.Encryption)
		}

		if hitgen.CurveId > 0 {
			args = append(args, "-curve ", strconv.Itoa(int(hitgen.CurveId)))
		}
		if hitgen.HitSuitId > 0 {
			args = append(args, "-suite ", strconv.Itoa(int(hitgen.HitSuitId)))
		}
		if hitgen.Bits > 0 {
			args = append(args, "-suite ", strconv.Itoa(int(hitgen.Bits)))
		}
		if hitgen.Length > 0 {
			args = append(args, "-length", strconv.Itoa(int(hitgen.Length)))
		}
		if hitgen.IsAnon {
			args = append(args, "-anon")
		}
		if hitgen.IsIncoming {
			args = append(args, "-incoming")
		}
		if hitgen.R1Count > 0 {
			args = append(args, "-r1count")
		}
		if hitgen.FilePath != "" {
			args = append(args, "-file", hitgen.FilePath)
		}
		if hitgen.IsPublish {
			args = append(args, "-publish")
		}
		if hitgen.IsConf {
			args = append(args, "-conf")
		}
		if hitgen.IsAppend {
			args = append(args, "-append")
		}
		if hitgen.Hhit != "" {
			args = append(args, "-hhit", hitgen.Hhit)
		}
	} else {
		args = append(args, "-conf")
	}
	output, err := CmdAndChangeDir(dir, "./hitgen", args)
	if err != nil {
		return err
	}
	if output != "" {
		return fmt.Errorf(output)
	}
	return nil
}

func InitHip() error {
	dir := "/usr/local/sbin/"
	confargs := []string{"-conf"}
	identities_args := []string{"RSA", "-name", "softball", "-bits", "1024"}
	domain_host_args := []string{"-publish"}

	output, err := CmdAndChangeDir(dir, "./hitgen", confargs)
	if err != nil {
		return err
	}
	if output != "" {
		return fmt.Errorf(output)
	}

	output, err = CmdAndChangeDir(dir, "./hitgen", identities_args)
	if err != nil {
		return err
	}
	if output != "" {
		return fmt.Errorf(output)
	}
	output, err = CmdAndChangeDir(dir, "./hitgen", domain_host_args)
	if err != nil {
		return err
	}
	if output != "" {
		return fmt.Errorf(output)
	}
	return nil
}

func CmdAndChangeDir(dir string, commandName string, params []string) (string, error) {
	cmd := exec.Command(commandName, params...)
	fmt.Println("CmdAndChangeDir", dir, cmd.Args)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	cmd.Dir = dir
	err := cmd.Start()
	if err != nil {
		return "", err
	}
	err = cmd.Wait()
	return out.String(), err
}
