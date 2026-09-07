package keysource

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nathants/go-libsodium"
)

func TestSources(t *testing.T) {
	libsodium.Init()
	pk, sk, err := libsodium.BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	secret := hex.EncodeToString(sk)
	for _, name := range []string{ValueEnv, FileEnv, CommandEnv} {
		t.Setenv(name, "")
	}
	if _, err := Load(context.Background(), ""); err == nil {
		t.Fatal("accepted no source")
	}
	t.Setenv(ValueEnv, secret)
	check := func() {
		t.Helper()
		ring, err := Load(context.Background(), "aws://example/test")
		if err != nil {
			t.Fatal(err)
		}
		var cipher bytes.Buffer
		if err := libsodium.StreamEncryptRecipients([][]byte{pk}, strings.NewReader("secret source"), &cipher); err != nil {
			t.Fatal(err)
		}
		if err := ring.Decrypt(&cipher, io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	check()
	t.Setenv(CommandEnv, "nonexistent")
	if _, err := Load(context.Background(), ""); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("conflict was not safely rejected")
	}
	t.Setenv(CommandEnv, "")
	t.Setenv(ValueEnv, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "private")
	if err := os.WriteFile(path, []byte(secret+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(FileEnv, path)
	check()
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), ""); err == nil {
		t.Fatal("accepted public secret file")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	t.Setenv(FileEnv, link)
	if _, err := Load(context.Background(), ""); err == nil {
		t.Fatal("followed key symlink")
	}
	t.Setenv(FileEnv, "")
	command := filepath.Join(dir, "source")
	if err := os.WriteFile(command, []byte("#!/bin/sh\n[ \"$1\" = aws://example/test ] || exit 2\ncat \""+path+"\"\n"), 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv(CommandEnv, command)
	check()
	if err := os.WriteFile(command, []byte("#!/bin/sh\nprintf '"+secret+"' >&2\nexit 1\n"), 0700); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(context.Background(), ""); err == nil || strings.Contains(err.Error(), secret) {
		t.Fatal("command failure exposed secret")
	}
}

func TestCommandOutputBound(t *testing.T) {
	var out boundedOutput
	// Match exec's io.Copy path, including its ReaderFrom optimization.
	source := struct{ io.Reader }{strings.NewReader(strings.Repeat("x", libsodium.MaxKeyChainsBytes+1))}
	if _, err := io.Copy(&out, source); err == nil {
		t.Fatal("command output limit bypassed")
	}
}
