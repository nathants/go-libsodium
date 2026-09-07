package libsodium

import (
	"bytes"
	"encoding/hex"
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
)

func TestKeyChainsRotation(t *testing.T) {
	Init()
	p1, s1, err := RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p2, s2, err := RotateKeyChain(p1, s1)
	if err != nil {
		t.Fatal(err)
	}
	ring, err := s2.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	for generation, public := range []KeyChains{p1, p2} {
		latest, err := public.Latest()
		if err != nil {
			t.Fatal(err)
		}
		var cipher, plain bytes.Buffer
		if err := StreamEncryptRecipients(latest, strings.NewReader("historical data"), &cipher); err != nil {
			t.Fatal(err)
		}
		if err := ring.Decrypt(bytes.NewReader(cipher.Bytes()), &plain); err != nil {
			t.Fatal(err)
		}
		if plain.String() != "historical data" {
			t.Fatal("wrong plaintext")
		}
		oldRing, err := s1.Keyring()
		if err != nil {
			t.Fatal(err)
		}
		oldErr := oldRing.Decrypt(bytes.NewReader(cipher.Bytes()), io.Discard)
		if (oldErr == nil) != (generation == 0) {
			t.Fatalf("old key at generation %d: %v", generation, oldErr)
		}
		selected, err := NewKeyring([][]byte{s2[0][generation]})
		if err != nil {
			t.Fatal(err)
		}
		if err := selected.Decrypt(bytes.NewReader(cipher.Bytes()), io.Discard); err != nil {
			t.Fatal(err)
		}
	}
	if err := ValidateKeyChainTransition(p1, p2); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyChainTransition(p2, p1); err == nil {
		t.Fatal("accepted truncation")
	}
	otherP, otherS, err := RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := RotateKeyChain(p1, otherS); err == nil {
		t.Fatal("accepted mismatched pair")
	}
	if err := ValidateKeyChainTransition(p2, otherP); err != nil {
		t.Fatal("whole recipient replacement should be allowed:", err)
	}
	if err := ValidateKeyChainTransition(p2, nil); err == nil {
		t.Fatal("accepted empty recipients")
	}
	if _, _, err := RotateKeyChain(p2, s1); err == nil {
		t.Fatal("accepted missing generation")
	}
	if _, _, err := RotateKeyChain(p1, nil); err == nil {
		t.Fatal("accepted missing private chain")
	}
}

func TestKeyChainsCanonical(t *testing.T) {
	a, b := strings.Repeat("1", 64), strings.Repeat("2", 64)
	good := a + ":" + b + "\n"
	for _, item := range []struct{ input, output string }{
		{"", ""}, {"\n\n", ""}, {good, good}, {a, a + "\n"},
		{"\n" + a + "\n\n" + b, a + "\n" + b + "\n"},
		{b + "\n" + a + "\n", b + "\n" + a + "\n"},
	} {
		chains, err := ParseKeyChains(strings.NewReader(item.input))
		if err != nil {
			t.Fatal(err)
		}
		out, err := chains.MarshalText()
		if err != nil || string(out) != item.output {
			t.Fatalf("round trip: %v", err)
		}
	}
	for _, bad := range []string{a + "\r\n", a + "\r", "\r\n", strings.Repeat("A", 64) + "\n", a + ":\n", a + ":" + a + "\n", a + "\n" + a + ":" + b + "\n", " " + a + "\n", strings.Repeat(a+":", MaxKeyGenerations) + b + "\n"} {
		if _, err := ParseKeyChains(strings.NewReader(bad)); err == nil {
			t.Fatalf("accepted invalid input of length %d", len(bad))
		}
	}
}

func TestExistingCiphertextFixture(t *testing.T) {
	Init()
	// Written by unmodified go-libsodium 4e1a79aae4f3, not this implementation.
	cipher, err := os.ReadFile("testdata/pre-keychains.ciphertext")
	if err != nil {
		t.Fatal(err)
	}
	secret, err := hex.DecodeString(strings.Repeat("03", 32))
	if err != nil {
		t.Fatal(err)
	}
	_, next, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	ring, err := NewKeyring([][]byte{next, secret})
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if err := ring.Decrypt(bytes.NewReader(cipher), &plain); err != nil {
		t.Fatal(err)
	}
	if plain.String() != "pre-keychains ciphertext compatibility\n" {
		t.Fatal("wrong fixture plaintext")
	}
	// Raw X25519 secrets differing only in ignored scalar bits share an identity.
	alias := bytes.Clone(secret)
	alias[0] ^= 1
	if _, err := NewKeyring([][]byte{secret, alias}); err == nil {
		t.Fatal("accepted duplicate secret identity")
	}
}

func FuzzKeyChains(f *testing.F) {
	f.Add([]byte(strings.Repeat("1", 64) + "\n"))
	f.Add([]byte(strings.Repeat("1", 64) + ":" + strings.Repeat("2", 64) + "\n"))
	f.Fuzz(func(t *testing.T, data []byte) {
		chains, err := ParseKeyChains(bytes.NewReader(data))
		if err != nil {
			return
		}
		out, err := chains.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		reparsed, err := ParseKeyChains(bytes.NewReader(out))
		if err != nil || !reflect.DeepEqual(chains, reparsed) {
			t.Fatalf("key-chain roundtrip changed recipients or generations: %v", err)
		}
		again, err := reparsed.MarshalText()
		if err != nil || !bytes.Equal(out, again) {
			t.Fatalf("key-chain serialization is not stable: %v", err)
		}
	})
}

func TestKeyChainTransitionIgnoresRecipientRowOrder(t *testing.T) {
	a, b, c := bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)
	old := KeyChains{{a}, {b}}
	next := KeyChains{{b, c}, {a}}
	if err := ValidateKeyChainTransition(old, next); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyChainTransition(next, old); err == nil {
		t.Fatal("row reordering concealed a truncated generation chain")
	}
	if _, err := ParseKeyChains(strings.NewReader(strings.Repeat("\n", MaxKeyChainsBytes+1))); err == nil {
		t.Fatal("blank lines bypassed the raw input bound")
	}
}
