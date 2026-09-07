package keysource

import (
	"context"
	"os"
	"os/exec"
	"testing"

	"github.com/nathants/go-libsodium"
)

func TestCommandCallerLifecycle(t *testing.T) {
	if os.Getenv("KEYSOURCE_TEST_CHILD") == "1" {
		libsodium.Init()
		_, err := Load(context.Background(), "")
		if err != nil {
			os.Exit(1)
		}
		return
	}
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KEYSOURCE_TEST_CHILD", "1")
	cmd := exec.Command("python3", "-I", "testdata/command-lifecycle.py", binary, "-test.run=^TestCommandCallerLifecycle$")
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("secret command lifecycle: %v\n%s", err, output)
	}
}
