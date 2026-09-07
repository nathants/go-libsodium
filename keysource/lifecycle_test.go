package keysource

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/nathants/go-libsodium"
	"golang.org/x/sys/unix"
)

func clearSources(t *testing.T) {
	t.Helper()
	for _, name := range []string{ValueEnv, FileEnv, CommandEnv} {
		t.Setenv(name, "")
	}
}

func TestLoadCanceledCommandTerminatesChildren(t *testing.T) {
	clearSources(t)
	dir := t.TempDir()
	loader := filepath.Join(dir, "loader")
	pidfile := filepath.Join(dir, "child")
	// The child retains inherited pipes. Its marker proves cancellation is tested
	// after it starts, rather than relying on startup timing.
	script := "#!/bin/sh\nsleep 10 &\nprintf '%s' $! > '" + pidfile + "'\nwait\n"
	if err := os.WriteFile(loader, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CommandEnv, loader)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := Load(ctx, ""); result <- err }()
	deadline := time.Now().Add(5 * time.Second)
	var pid int
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(pidfile)
		if err == nil {
			pid, _ = strconv.Atoi(string(raw))
			if pid > 0 {
				break
			}
		}
		time.Sleep(5 * time.Millisecond)
	}
	if pid == 0 {
		t.Fatal("child did not start")
	}
	t.Cleanup(func() { _ = unix.Kill(pid, unix.SIGKILL) })
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Errorf("cancellation identity lost: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("cancellation blocked on inherited pipes")
	}
	// A killed child may briefly remain a zombie until the host's init reaps it.
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err == nil {
		_, rest, _ := strings.Cut(string(stat), ") ")
		if !strings.HasPrefix(rest, "Z ") {
			t.Fatal("child survived cancellation")
		}
	}
}

func TestLoadCommandFailuresAreSafeAndDistinct(t *testing.T) {
	clearSources(t)
	dir := t.TempDir()
	loader := filepath.Join(dir, "loader")
	t.Setenv(CommandEnv, loader)
	if _, err := Load(context.Background(), ""); err == nil || !strings.Contains(err.Error(), "unavailable") || strings.Contains(err.Error(), loader) {
		t.Fatalf("unsafe/opaque missing executable error: %v", err)
	}
	for _, item := range []struct{ script, want string }{
		{"printf 'SYNTHETIC-SECRET' >&2; exit 7", "exit status 7"},
		{"head -c 5000000 /dev/zero; sleep 10", "exceeds limit"},
		{"sleep 10 & exit 0", "pipes"},
	} {
		if err := os.WriteFile(loader, []byte("#!/bin/sh\n"+item.script+"\n"), 0700); err != nil {
			t.Fatal(err)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		_, err := Load(ctx, "")
		cancel()
		if err == nil || !strings.Contains(err.Error(), item.want) || strings.Contains(err.Error(), "SYNTHETIC-SECRET") || strings.Contains(err.Error(), loader) {
			t.Errorf("want safe category %q, got %v", item.want, err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := Load(ctx, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("already canceled: %v", err)
	}
}

func TestLoadSourceGuards(t *testing.T) {
	libsodium.Init()
	clearSources(t)
	dir := t.TempDir()
	marker := filepath.Join(dir, "executed")
	loader := filepath.Join(dir, "loader")
	if err := os.WriteFile(loader, []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CommandEnv, loader)
	t.Setenv(ValueEnv, strings.Repeat("1", 64))
	if _, err := Load(context.Background(), ""); err == nil {
		t.Fatal("conflict accepted")
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("conflicting command executed")
	}
	t.Setenv(CommandEnv, "")
	t.Setenv(ValueEnv, "")
	for _, kind := range []string{"directory", "fifo", "oversized"} {
		path := filepath.Join(dir, kind)
		switch kind {
		case "directory":
			if err := os.Mkdir(path, 0700); err != nil {
				t.Fatal(err)
			}
		case "fifo":
			if err := unix.Mkfifo(path, 0600); err != nil {
				t.Fatal(err)
			}
		default:
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Truncate(libsodium.MaxKeyChainsBytes + 1); err != nil {
				t.Fatal(err)
			}
			if err = f.Close(); err != nil {
				t.Fatal(err)
			}
		}
		t.Setenv(FileEnv, path)
		if _, err := Load(context.Background(), ""); err == nil {
			t.Fatalf("accepted %s", kind)
		}
	}
	public, secret, err := libsodium.RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	public, secret, err = libsodium.RotateKeyChain(public, secret)
	if err != nil {
		t.Fatal(err)
	}
	text, err := secret.MarshalText()
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "private")
	if err := os.WriteFile(path, text, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(FileEnv, path)
	ring, err := Load(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range public[0] {
		var cipher, plain bytes.Buffer
		if err := libsodium.StreamEncryptRecipients([][]byte{key}, strings.NewReader("source history"), &cipher); err != nil {
			t.Fatal(err)
		}
		if err := ring.Decrypt(&cipher, &plain); err != nil || plain.String() != "source history" {
			t.Fatalf("source history: %v", err)
		}
	}
}

func TestKeyFilePermissionContract(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "key")
	if err := os.WriteFile(path, []byte(strings.Repeat("1", 64)), 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []os.FileMode{0400, 0600, 0644, 0700, 0640, 0622, 0600 | os.ModeSetuid, 0600 | os.ModeSetgid, 0600 | os.ModeSticky} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := ReadFile(path, true)
		want := mode == 0400 || mode == 0600
		if (err == nil) != want {
			t.Errorf("private mode %v accepted=%t", mode, err == nil)
		}
	}
	for _, mode := range []os.FileMode{0400, 0600, 0644, 0664, 0666} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
		_, err := ReadFile(path, false)
		want := mode&0022 == 0
		if (err == nil) != want {
			t.Errorf("public mode %v accepted=%t", mode, err == nil)
		}
	}
}
