package libsodium

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
)

// KeyChains contains one individual's generations per row, oldest first.
// Public and secret chains use the same syntax but must never share a file.
type KeyChains [][][]byte

const (
	MaxKeyGenerations = 1024
	MaxChainKeys      = 65536
	MaxKeyChainsBytes = MaxChainKeys * 65
)

// ParseKeyChains reads lowercase hex generations separated by colons and
// recipient rows separated by LF. Row order is insignificant and preserved;
// generations remain oldest first. Blank lines and a missing final LF are allowed.
// Empty input is valid local preparation; encryption still requires recipients.
func ParseKeyChains(input io.Reader) (KeyChains, error) {
	r := &io.LimitedReader{R: input, N: MaxKeyChainsBytes + 1}
	scanner := bufio.NewScanner(r)
	// Unlike ScanLines, retain CR so malformed CRLF input is rejected.
	scanner.Split(func(data []byte, atEOF bool) (int, []byte, error) {
		if i := bytes.IndexByte(data, '\n'); i >= 0 {
			return i + 1, data[:i], nil
		}
		if atEOF && len(data) != 0 {
			return len(data), data, nil
		}
		return 0, nil, nil
	})
	scanner.Buffer(make([]byte, 4096), MaxKeyGenerations*65+1)
	var chains KeyChains
	validator := keyChainValidator{}
	for scanner.Scan() {
		line := scanner.Text()
		if len(line) == 0 {
			continue
		}
		if len(line) > MaxKeyGenerations*65-1 {
			return nil, fmt.Errorf("invalid key chain length at row %d", len(chains)+1)
		}
		var chain [][]byte
		for value := range strings.SplitSeq(line, ":") {
			if len(value) != 64 || strings.IndexFunc(value, func(c rune) bool { return !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') }) >= 0 {
				return nil, fmt.Errorf("invalid key at row %d generation %d: expected 64 lowercase hex characters", len(chains)+1, len(chain)+1)
			}
			key, err := hex.DecodeString(value)
			if err != nil {
				return nil, fmt.Errorf("invalid key encoding")
			}
			chain = append(chain, key)
		}
		if err := validator.chain(chain); err != nil {
			return nil, err
		}
		chains = append(chains, chain)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read key chains: %w", err)
	}
	if r.N <= 0 {
		return nil, fmt.Errorf("key chains exceed byte limit")
	}
	return chains, nil
}

// keyChainValidator shares native structural checks between text parsing and
// in-memory operations. It never serializes or includes key material in errors.
type keyChainValidator struct {
	total int
	seen  map[[32]byte]struct{}
}

func (v *keyChainValidator) chain(chain [][]byte) error {
	if len(chain) == 0 || len(chain) > MaxKeyGenerations {
		return fmt.Errorf("invalid key generation count")
	}
	if len(chain) > MaxChainKeys-v.total {
		return fmt.Errorf("key chains exceed %d total keys", MaxChainKeys)
	}
	if v.seen == nil {
		v.seen = make(map[[32]byte]struct{})
	}
	for i, key := range chain {
		if len(key) != 32 {
			return fmt.Errorf("invalid key size at generation %d", i+1)
		}
		identity := [32]byte(key)
		if _, found := v.seen[identity]; found {
			return fmt.Errorf("duplicate key at generation %d", i+1)
		}
		v.seen[identity] = struct{}{}
	}
	v.total += len(chain)
	return nil
}

func (chains KeyChains) validate() error {
	v := keyChainValidator{}
	for _, chain := range chains {
		if err := v.chain(chain); err != nil {
			return err
		}
	}
	return nil
}

// MarshalText validates and serializes chains without reordering generations.
func (chains KeyChains) MarshalText() ([]byte, error) {
	if err := chains.validate(); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	for _, chain := range chains {
		for i, key := range chain {
			if i != 0 {
				out.WriteByte(':')
			}
			out.WriteString(hex.EncodeToString(key))
		}
		out.WriteByte('\n')
	}
	return out.Bytes(), nil
}

// Latest returns the current generation of every recipient, for new encryption.
func (chains KeyChains) Latest() ([][]byte, error) {
	if err := chains.validate(); err != nil {
		return nil, err
	}
	if len(chains) == 0 {
		return nil, fmt.Errorf("recipient list is empty")
	}
	keys := make([][]byte, 0, len(chains))
	for _, chain := range chains {
		keys = append(keys, bytes.Clone(chain[len(chain)-1]))
	}
	return keys, nil
}

// ValidateKeyChainTransition permits adding/removing recipients and appending
// generations. A retained first-generation identity cannot truncate or rewrite
// its chain. These are structural checks, not signed proof of succession.
func ValidateKeyChainTransition(old, next KeyChains) error {
	if err := old.validate(); err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return err
	}
	if len(next) == 0 {
		return fmt.Errorf("recipient list is empty")
	}
	previous := make(map[string][][]byte, len(old))
	for _, chain := range old {
		previous[string(chain[0])] = chain
	}
	for _, chain := range next {
		if before, ok := previous[string(chain[0])]; ok {
			if len(chain) < len(before) {
				return fmt.Errorf("recipient chain was truncated")
			}
			for i, key := range before {
				if !bytes.Equal(key, chain[i]) {
					return fmt.Errorf("recipient chain generation %d was replaced", i+1)
				}
			}
		}
	}
	return nil
}

// RotateKeyChain validates one personal public/private pair, then returns both
// extended chains. Persistence is the caller's responsibility, private first.
func RotateKeyChain(public, secret KeyChains) (KeyChains, KeyChains, error) {
	if err := public.validate(); err != nil {
		return nil, nil, err
	}
	if err := secret.validate(); err != nil {
		return nil, nil, err
	}
	if len(public) != len(secret) || len(public) > 1 {
		return nil, nil, fmt.Errorf("expected one personal public/private chain pair")
	}
	var p, s [][]byte
	if len(public) == 1 {
		p, s = public[0], secret[0]
		if len(p) != len(s) {
			return nil, nil, fmt.Errorf("public/private generation counts differ")
		}
		if len(p) >= MaxKeyGenerations {
			return nil, nil, fmt.Errorf("key generation limit reached")
		}
		for i := range p {
			derived, err := BoxPublicKey(s[i])
			if err != nil {
				return nil, nil, err
			}
			if !bytes.Equal(derived, p[i]) {
				return nil, nil, fmt.Errorf("public/private generation %d does not match", i+1)
			}
		}
	}
	pk, sk, err := BoxKeypair()
	if err != nil {
		return nil, nil, err
	}
	return KeyChains{append(cloneGenerations(p), pk)}, KeyChains{append(cloneGenerations(s), sk)}, nil
}

func cloneGenerations(chain [][]byte) [][]byte {
	result := make([][]byte, len(chain), len(chain)+1)
	for i, key := range chain {
		result[i] = bytes.Clone(key)
	}
	return result
}
