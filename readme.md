[![Go Reference](https://pkg.go.dev/badge/github.com/nathants/go-libsodium.svg)](https://pkg.go.dev/github.com/nathants/go-libsodium)

# Go-Libsodium

## Why

Libsodium should be easy.

## How

A minimal cgo interface to the following Libsodium constructs:

- [crypt_box_easy](https://doc.libsodium.org/secret-key_cryptography/secretbox)

- [crypto_box_seal](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)

- [crypto_sign](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)

- [crypto_stream](https://doc.libsodium.org/secret-key_cryptography/secretstream)

## What

```go

func Init()

func StreamKeygen() (key []byte, err error)

func StreamEncrypt(key []byte, plainText io.Reader, cipherText io.Writer) error

func StreamDecrypt(key []byte, cipherText io.Reader, plainText io.Writer) error

func StreamEncryptRecipients(publicKeys [][]byte, plainText io.Reader, cipherText io.Writer) error

func NewKeyring(secretKeys [][]byte) (*Keyring, error)
func (ring *Keyring) Decrypt(cipherText io.Reader, plainText io.Writer) error

func BoxKeypair() (publicKey, secretKey []byte, err error)

func BoxSealedEncrypt(plainText, recipientPublicKey []byte) (cipherText []byte, err error)

func BoxSealedDecrypt(cipherText, recipientSecretKey []byte) (plainText []byte, err error)

func BoxEasyEncrypt(plainText, recipientPublicKey, senderSecretKey []byte) (cipherText []byte, err error)

func BoxEasyDecrypt(cipherText, senderPublicKey, recipientSecretKey []byte) (plainText []byte, err error)

func SignKeypair() (publicKey, secretKey []byte, err error)

func Sign(plainText, signerSecretKey []byte) (signedText []byte, err error)

func SignVerify(signedText, plainText, signerPublicKey []byte) error

```

## Install

Requires Go 1.27+ and Libsodium. The `keysource` subpackage requires Linux.

```bash
brew install         go     libsodium     # homebrew
sudo pacman -S       go     libsodium     # arch
sudo apk add         go     libsodium-dev # alpine
sudo apt-get install golang libsodium-dev # ubuntu/debian
```

```bash
go get github.com/nathants/go-libsodium
```

## Usage

```go
package main

import (
	"bytes"
	"fmt"

	"github.com/nathants/go-libsodium"
)

func Stream() {
	libsodium.Init()
	key, err := libsodium.StreamKeygen()
	if err != nil {
		panic(err)
	}
	value := []byte("hello world")
	var cipher bytes.Buffer
	err = libsodium.StreamEncrypt(key, bytes.NewReader(value), &cipher)
	if err != nil {
		panic(err)
	}
	var plain bytes.Buffer
	err = libsodium.StreamDecrypt(key, bytes.NewReader(cipher.Bytes()), &plain)
	if err != nil {
		panic(err)
	}
	fmt.Println("stream", bytes.Equal(value, plain.Bytes()))
}

func StreamRecipients() {
	libsodium.Init()
	pk1, sk1, err := libsodium.BoxKeypair()
	if err != nil {
		panic(err)
	}
	pk2, sk2, err := libsodium.BoxKeypair()
	if err != nil {
		panic(err)
	}
	value := []byte("hello world")
	var cipher bytes.Buffer
	err = libsodium.StreamEncryptRecipients([][]byte{pk1, pk2}, bytes.NewReader(value), &cipher)
	if err != nil {
		panic(err)
	}
	var plain bytes.Buffer
	ring1, err := libsodium.NewKeyring([][]byte{sk1})
	if err != nil {
		panic(err)
	}
	err = ring1.Decrypt(bytes.NewReader(cipher.Bytes()), &plain)
	if err != nil {
		panic(err)
	}
	fmt.Println("recipient1", bytes.Equal(value, plain.Bytes()))
	plain.Reset()
	ring2, err := libsodium.NewKeyring([][]byte{sk2})
	if err != nil {
		panic(err)
	}
	err = ring2.Decrypt(bytes.NewReader(cipher.Bytes()), &plain)
	if err != nil {
		panic(err)
	}
	fmt.Println("recipient2", bytes.Equal(value, plain.Bytes()))
}

func BoxSeal() {
	libsodium.Init()
	value := []byte("hello world")
	pk, sk, err := libsodium.BoxKeypair()
	if err != nil {
	    panic(err)
	}
	cipher, err := libsodium.BoxSealedEncrypt(value, pk)
	if err != nil {
	    panic(err)
	}
	plain, err := libsodium.BoxSealedDecrypt(cipher, sk)
	if err != nil {
	    panic(err)
	}
	fmt.Println("seal", bytes.Equal(value, plain))
}

func BoxEasy() {
	value := []byte("hello world")
	pk1, sk1, err := libsodium.BoxKeypair()
	if err != nil {
	    panic(err)
	}
	pk2, sk2, err := libsodium.BoxKeypair()
	if err != nil {
	    panic(err)
	}
	cipher, err := libsodium.BoxEasyEncrypt(value, pk2, sk1)
	if err != nil {
	    panic(err)
	}
	plain, err := libsodium.BoxEasyDecrypt(cipher, pk1, sk2)
	if err != nil {
	    panic(err)
	}
	fmt.Println("easy", bytes.Equal(value, plain))
}

func Sign() {
	value := []byte("hello world")
	pk, sk, err := libsodium.SignKeypair()
	if err != nil {
	    panic(err)
	}
	signature, err := libsodium.Sign(value, sk)
	if err != nil {
	    panic(err)
	}
	err = libsodium.SignVerify(signature, value, pk)
	if err != nil {
	    panic(err)
	}
	fmt.Println("signature")
}

func main() {
	Stream()
	StreamRecipients()
	BoxSeal()
	BoxEasy()
	Sign()
}
```

## Recipient key chains

`KeyChains` (`[][][]byte`) stores one recipient per row, with generations oldest
first. `ParseKeyChains` and `KeyChains.MarshalText` use 64 lowercase hex characters
per key, colons between generations, and newlines between recipients.
Rows need not be sorted. Blank lines and a missing
final newline are allowed; serialization emits one newline per nonempty row.
Duplicates, comments, spaces, tabs, and CR are rejected. Limits: 1,024 generations
per row, 65,536 keys, and 4,259,840 input bytes. Parsing accepts empty input;
encryption and keyring construction require keys.

- `RotateKeyChain(public, secret)` creates a pair or validates and extends an
  existing pair. Returned buffers are independent; no files are written.
- `KeyChains.Latest()` selects public chain tips for `StreamEncryptRecipients`.
- `KeyChains.Keyring()` includes all supplied private generations for decryption.
- `BoxPublicKey(secret)` derives the corresponding public key.
- `ValidateKeyChainTransition(old, next)` allows recipient additions/removals and
  extensions, rejects edits within retained chains, and requires a nonempty result.
  It does not authenticate or sign rotations.

Retain historical secrets to decrypt historical ciphertext. Rotation does not
re-encrypt old data or revoke access to existing copies. The ciphertext format is
unchanged; replace calls to the removed `StreamDecryptRecipients` with
`NewKeyring` and `Keyring.Decrypt`.

## Secret loading (Linux)

`keysource.Load(ctx, remoteURL)` returns a keyring from exactly one nonempty source:

- `GIT_REMOTE_AWS_SECRETKEY`: private chain text.
- `GIT_REMOTE_AWS_SECRETKEY_FILE`: bounded regular file, not a symlink, with only
  owner read/write permissions.
- `GIT_REMOTE_AWS_SECRETKEY_CMD`: executable that prints private chains. It receives
  `remoteURL` when nonempty; commands are not evaluated by a shell.

Command output is bounded and omitted from errors. Cancellation, SIGINT/SIGTERM,
or output overflow terminates the command process group. Interactive commands
receive the foreground terminal; terminal-attached background loading is rejected.
Prompting has no deadline; inherited output pipes get 250ms to drain after exit.
This is not a process sandbox or a guarantee of cleanup after SIGKILL.

## Tests

Requires Python 3.8+ for executable/terminal tests.

```sh
bash bin/check.sh
go test -cover ./...
go test -race ./...
go test -run '^$' -fuzz '^FuzzKeyChains$' -fuzztime=10s
```

`testdata/pre-keychains.ciphertext` preserves compatibility coverage against
ciphertext generated by library revision `4e1a79aae4f3` with a public test-only key.
