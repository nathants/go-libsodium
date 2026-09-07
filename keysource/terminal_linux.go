package keysource

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"

	"golang.org/x/sys/unix"
)

// Foreground is set by Go in the child before exec, avoiding a race between the
// first terminal read and parent-side handoff. The returned cleanup also restores
// the terminal after an exec failure (which can occur after foreground handoff).
func commandTerminal(cmd *exec.Cmd) (func() error, error) {
	fd, err := unix.Open("/dev/tty", unix.O_RDWR|unix.O_CLOEXEC, 0)
	if errors.Is(err, unix.ENXIO) || errors.Is(err, unix.ENODEV) || errors.Is(err, unix.ENOENT) {
		return func() error { return nil }, nil // Detached commands have no terminal.
	}
	if err != nil {
		return nil, fmt.Errorf("open secret command terminal: %w", err)
	}
	group, err := unix.IoctlGetInt(fd, unix.TIOCGPGRP)
	if err != nil || group != unix.Getpgrp() {
		_ = unix.Close(fd)
		if err != nil {
			return nil, fmt.Errorf("inspect secret command terminal: %w", err)
		}
		return nil, fmt.Errorf("secret command requires a foreground terminal job or a detached invocation")
	}
	cmd.SysProcAttr.Foreground = true
	cmd.SysProcAttr.Ctty = fd
	return func() error {
		// tcsetpgrp from our now-background group requires blocking SIGTTOU.
		// Scope that mask to this OS thread; never change process-wide handlers.
		runtime.LockOSThread()
		defer runtime.UnlockOSThread()
		var mask, previous unix.Sigset_t
		mask.Val[0] = 1 << (uint(unix.SIGTTOU) - 1)
		if err := unix.PthreadSigmask(unix.SIG_BLOCK, &mask, &previous); err != nil {
			_ = unix.Close(fd)
			return fmt.Errorf("block terminal restoration signal: %w", err)
		}
		restoreErr := unix.IoctlSetPointerInt(fd, unix.TIOCSPGRP, group)
		maskErr := unix.PthreadSigmask(unix.SIG_SETMASK, &previous, nil)
		closeErr := unix.Close(fd)
		if err := errors.Join(restoreErr, maskErr, closeErr); err != nil {
			return fmt.Errorf("restore secret command terminal: %w", err)
		}
		return nil
	}, nil
}
