//go:build !windows

/*
Copyright 2026 Raj Singh.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"os/exec"
	"syscall"
)

// configureE2EProcess makes a bounded command and all of its descendants part
// of one process group. This matters for make and container clients: killing
// only the top-level process can leave a child holding CombinedOutput's pipe
// open after the timeout.
func configureE2EProcess(cmd *exec.Cmd) {
	groupKill := cmd.SysProcAttr == nil
	if groupKill {
		cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if groupKill {
			if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err == nil {
				return nil
			}
		}
		return cmd.Process.Kill()
	}
}
