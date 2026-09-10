package libsodium

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInitConcurrent(t *testing.T) {
	if os.Getenv("GO_LIBSODIUM_INIT_CHILD") != "1" {
		child := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestInitConcurrent$", "-test.timeout=15s")
		child.Env = append(os.Environ(), "GO_LIBSODIUM_INIT_CHILD=1")
		if output, err := child.CombinedOutput(); err != nil {
			t.Fatalf("concurrent initialization in a fresh process: %v\n%s", err, output)
		}
		return
	}
	const workers = 64
	start := make(chan struct{})
	failures := make(chan error, workers)
	var done sync.WaitGroup
	for range workers {
		done.Go(func() {
			defer func() {
				if value := recover(); value != nil {
					failures <- fmt.Errorf("initializer panicked: %v", value)
				}
			}()
			<-start
			// A readiness check may race the first initializer, but must either
			// reject use-before-init or observe fully initialized native state.
			if _, err := StreamKeygen(); err != nil && !strings.Contains(err.Error(), "forgot to init sodium") {
				failures <- err
				return
			}
			Init()
			Init()
			key, err := StreamKeygen()
			if err != nil {
				failures <- err
				return
			}
			var encrypted, restored bytes.Buffer
			if err := StreamEncrypt(key, strings.NewReader("concurrent init"), &encrypted); err != nil {
				failures <- err
				return
			}
			if err := StreamDecrypt(key, &encrypted, &restored); err != nil {
				failures <- err
				return
			}
			if restored.String() != "concurrent init" {
				failures <- fmt.Errorf("round trip after Init changed content")
			}
		})
	}
	close(start)
	done.Wait()
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}

func TestInitAfterNativeInitialization(t *testing.T) {
	binary := filepath.Join(t.TempDir(), "native-init")
	build := exec.CommandContext(t.Context(), "go", "build", "-o", binary, "./testdata/native-init")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build native initialization fixture: %v\n%s", err, output)
	}
	if output, err := exec.CommandContext(t.Context(), binary).CombinedOutput(); err != nil {
		t.Fatalf("accept successful prior native initialization: %v\n%s", err, output)
	}
}
