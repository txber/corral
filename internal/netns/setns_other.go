//go:build !amd64 && !386

package netns

import "syscall"

// sysSetns is the number of the setns system call.
const sysSetns = syscall.SYS_SETNS
