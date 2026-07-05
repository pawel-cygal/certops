package main

import (
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

func fleetSSHArgs(host fleetHost, remote string) []string {
	userHost := host.Address
	if strings.TrimSpace(host.User) != "" {
		userHost = host.User + "@" + host.Address
	}
	args := []string{
		"-o", "BatchMode=yes",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/tmp/certops-fleet-known-hosts",
	}
	if strings.TrimSpace(host.Port) != "" {
		args = append(args, "-p", host.Port)
	}
	if strings.TrimSpace(host.IdentityFile) != "" {
		args = append(args, "-i", host.IdentityFile)
	}
	args = append(args, userHost, remote)
	return args
}

func fleetSSH(host fleetHost, remote string, stdin []byte) ([]byte, error) {
	cmd := exec.Command("ssh", fleetSSHArgs(host, remote)...)
	if stdin != nil {
		cmd.Stdin = bytes.NewReader(stdin)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(out)))
	}
	return out, nil
}
