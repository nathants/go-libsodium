// Package keysource implements the shared, on-demand application key source.
// It does not generate keys or manage recipient files.
package keysource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/nathants/go-libsodium"
	"golang.org/x/sys/unix"
)

const (
	ValueEnv   = "GIT_REMOTE_AWS_SECRETKEY"
	FileEnv    = "GIT_REMOTE_AWS_SECRETKEY_FILE"
	CommandEnv = "GIT_REMOTE_AWS_SECRETKEY_CMD"
)

// Load evaluates exactly one configured source. The command is an executable,
// not shell text, and receives the remote URL when one is available. Failure
// never falls back, and neither captured output nor secrets enter diagnostics.
func Load(ctx context.Context, remoteURL string) (*libsodium.Keyring, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	value, file, command := os.Getenv(ValueEnv), os.Getenv(FileEnv), os.Getenv(CommandEnv)
	var names []string
	for _, name := range []string{ValueEnv, FileEnv, CommandEnv} {
		if os.Getenv(name) != "" {
			names = append(names, name)
		}
	}
	if len(names) != 1 {
		return nil, fmt.Errorf("exactly one of %s, %s, %s must be set (configured: %s)", ValueEnv, FileEnv, CommandEnv, strings.Join(names, ", "))
	}
	var chains libsodium.KeyChains
	var err error
	switch {
	case value != "":
		chains, err = libsodium.ParseKeyChains(strings.NewReader(value))
	case file != "":
		chains, err = ReadFile(file, true)
	default:
		args := []string{}
		if remoteURL != "" {
			args = append(args, remoteURL)
		}
		var output string
		output, err = commandOutput(ctx, command, args)
		if err == nil {
			chains, err = libsodium.ParseKeyChains(strings.NewReader(output))
		}
	}
	if err != nil {
		return nil, fmt.Errorf("%s: %w", names[0], err)
	}
	return chains.Keyring()
}

// Bound pipe draining after exit/cancellation, not time spent using pinentry.
// Process-group cleanup covers ordinary children, not deliberately escaped jobs.
func commandOutput(ctx context.Context, command string, args []string) (result string, returnErr error) {
	// This application loader owns signals only while an external secret command
	// runs. Do not swallow interrupts in unrelated, non-cancellable CLI work.
	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, command, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	restoreTerminal, err := commandTerminal(cmd)
	if err != nil {
		return "", err
	}
	defer func() {
		if err := restoreTerminal(); err != nil {
			result = ""
			returnErr = errors.Join(returnErr, err)
		}
	}()
	killGroup := func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		err := unix.Kill(-cmd.Process.Pid, unix.SIGKILL)
		if errors.Is(err, unix.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	cmd.Cancel = killGroup
	cmd.WaitDelay = 250 * time.Millisecond
	defer func() { _ = killGroup() }()
	output := boundedOutput{cancel: cancel}
	cmd.Stdout = &output
	cmd.Stderr = io.Discard
	err = cmd.Run()
	if ctx.Err() != nil {
		return "", ctx.Err()
	}
	if output.exceeded {
		return "", fmt.Errorf("secret command output exceeds limit")
	}
	if errors.Is(err, exec.ErrWaitDelay) {
		return "", fmt.Errorf("secret command output pipes remained open after exit")
	}
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", fmt.Errorf("secret command failed with exit status %d (output withheld)", exit.ExitCode())
		}
		// Start errors can contain the executable path; never expose it.
		return "", fmt.Errorf("secret command executable unavailable or could not start")
	}
	return output.String(), nil
}

type boundedOutput struct {
	buffer   bytes.Buffer
	exceeded bool
	cancel   context.CancelFunc
}

func (out *boundedOutput) String() string { return out.buffer.String() }

func (out *boundedOutput) Write(p []byte) (int, error) {
	if len(p) > libsodium.MaxKeyChainsBytes-out.buffer.Len() {
		out.exceeded = true
		if out.cancel != nil {
			out.cancel()
		}
		return 0, fmt.Errorf("secret command output exceeds limit")
	}
	return out.buffer.Write(p)
}

// ReadFile refuses symlinks, special files, and unsafe permissions. A caller
// must exclusively control the containing namespace during key management.
func ReadFile(path string, private bool) (libsodium.KeyChains, error) {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	defer func() { _ = f.Close() }()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	forbidden := os.FileMode(0022)
	if private {
		forbidden = 0177 | os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	}
	if !info.Mode().IsRegular() || info.Mode()&forbidden != 0 || info.Size() > libsodium.MaxKeyChainsBytes {
		return nil, fmt.Errorf("key file must be bounded, regular, and have safe permissions")
	}
	return libsodium.ParseKeyChains(f)
}
