package libsodium

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"reflect"
	"strings"
	"testing"
)

func TestRotationOwnsHistoricalBuffers(t *testing.T) {
	Init()
	p, s, err := RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	p2, s2, err := RotateKeyChain(p, s)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(p[0][0], p2[0][0]) || !bytes.Equal(s[0][0], s2[0][0]) {
		t.Fatal("rotation changed history")
	}
	var cipher bytes.Buffer
	if err := StreamEncryptRecipients([][]byte{p[0][0]}, strings.NewReader("history"), &cipher); err != nil {
		t.Fatal(err)
	}
	clear(p[0][0])
	clear(s[0][0])
	ring, err := s2.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if err := ring.Decrypt(&cipher, &plain); err != nil || plain.String() != "history" {
		t.Fatalf("input mutation corrupted returned history: %v", err)
	}
	p3, s3, err := RotateKeyChain(p2, s2)
	if err != nil {
		t.Fatal(err)
	}
	oldP, oldS := bytes.Clone(p2[0][0]), bytes.Clone(s2[0][0])
	clear(p3[0][0])
	clear(s3[0][0])
	if !bytes.Equal(oldP, p2[0][0]) || !bytes.Equal(oldS, s2[0][0]) {
		t.Fatal("returned mutation corrupted input history")
	}
}

func distinctChains(count, perRow int) KeyChains {
	var result KeyChains
	for i := 0; i < count; i++ {
		if i%perRow == 0 {
			result = append(result, nil)
		}
		key := make([]byte, 32)
		binary.LittleEndian.PutUint64(key, uint64(i+1))
		result[len(result)-1] = append(result[len(result)-1], key)
	}
	return result
}

func TestKeyChainExactLimitsAndInvalidStructures(t *testing.T) {
	for _, n := range []int{MaxKeyGenerations, MaxChainKeys} {
		chains := distinctChains(n, MaxKeyGenerations)
		text, err := chains.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		got, err := ParseKeyChains(bytes.NewReader(text))
		if err != nil || !reflect.DeepEqual(chains, got) {
			t.Fatalf("valid limit %d rejected: %v", n, err)
		}
	}
	for _, chains := range []KeyChains{
		{nil}, {{{1}}}, {{make([]byte, 32), make([]byte, 32)}},
		distinctChains(MaxKeyGenerations+1, MaxKeyGenerations+1), distinctChains(MaxChainKeys+1, MaxKeyGenerations),
	} {
		if _, err := chains.MarshalText(); err == nil {
			t.Fatal("invalid structure serialized")
		}
		if _, err := chains.Latest(); err == nil {
			t.Fatal("invalid structure selected")
		}
		if _, err := chains.Keyring(); err == nil {
			t.Fatal("invalid structure became a keyring")
		}
	}
	// Build limit+one text from individually valid rows, without an invalid
	// serializer or duplicate keys masking the actual parser boundaries.
	chain := distinctChains(MaxKeyGenerations+1, 1)
	var rows []string
	for _, row := range chain {
		text, err := KeyChains{row}.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		rows = append(rows, strings.TrimSuffix(string(text), "\n"))
	}
	if _, err := ParseKeyChains(strings.NewReader(strings.Join(rows, ":") + "\n")); err == nil {
		t.Fatal("generation limit+one accepted")
	}
	total := distinctChains(MaxChainKeys+1, MaxKeyGenerations)
	var text bytes.Buffer
	for _, row := range total {
		part, err := KeyChains{row}.MarshalText()
		if err != nil {
			t.Fatal(err)
		}
		text.Write(part)
	}
	if _, err := ParseKeyChains(&text); err == nil {
		t.Fatal("total key limit+one accepted")
	}
	sentinel := errors.New("reader failure")
	if _, err := ParseKeyChains(io.MultiReader(strings.NewReader(strings.Repeat("1", 64)+"\n"), brokenKeyReader{sentinel})); !errors.Is(err, sentinel) {
		t.Fatalf("lost reader error: %v", err)
	}
}

type brokenKeyReader struct{ err error }

func (r brokenKeyReader) Read([]byte) (int, error) { return 0, r.err }

func TestMixedRecipientsAndKeyrings(t *testing.T) {
	Init()
	a, sa, err := RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	b, sb, err := RotateKeyChain(nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a2, sa2, err := RotateKeyChain(a, sa)
	if err != nil {
		t.Fatal(err)
	}
	old, next := KeyChains{a[0], b[0]}, KeyChains{b[0], a2[0]}
	if err := ValidateKeyChainTransition(old, next); err != nil {
		t.Fatal(err)
	}
	if err := ValidateKeyChainTransition(next, b); err != nil {
		t.Fatal(err)
	}
	replaced := KeyChains{[][]byte{a[0][0], b[0][0]}}
	if err := ValidateKeyChainTransition(a2, replaced); err == nil {
		t.Fatal("replaced generation accepted")
	}
	keys, err := next.Latest()
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 || !bytes.Equal(keys[0], b[0][0]) || !bytes.Equal(keys[1], a2[0][1]) {
		t.Fatal("wrong current recipients")
	}
	var ciphertext bytes.Buffer
	if err := StreamEncryptRecipients(keys, strings.NewReader("multiple recipients"), &ciphertext); err != nil {
		t.Fatal(err)
	}
	for _, secrets := range []KeyChains{sa2, sb, {sa2[0], sb[0]}} {
		ring, err := secrets.Keyring()
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		// Hide Seek: decryption must work in one pass, including two matching headers.
		input := struct{ io.Reader }{bytes.NewReader(ciphertext.Bytes())}
		if err := ring.Decrypt(input, &out); err != nil || out.String() != "multiple recipients" {
			t.Fatalf("multi-recipient decrypt: %v", err)
		}
	}
	oldRing, err := sa.Keyring()
	if err != nil {
		t.Fatal(err)
	}
	if err := oldRing.Decrypt(bytes.NewReader(ciphertext.Bytes()), io.Discard); err == nil {
		t.Fatal("retired key decrypted new content")
	}
	for _, keys := range [][][]byte{nil, {{1}}, {make([]byte, 32), make([]byte, 32)}} {
		if _, err := NewKeyring(keys); err == nil {
			t.Fatal("invalid secrets accepted")
		}
	}
	for _, ring := range []*Keyring{nil, {}} {
		if err := ring.Decrypt(bytes.NewReader(nil), io.Discard); err == nil {
			t.Fatal("empty keyring accepted")
		}
	}
}
