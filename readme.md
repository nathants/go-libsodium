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

func StreamDecryptRecipients(secretKey []byte, cipherText io.Reader, plainText io.Writer) error

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
	err = libsodium.StreamDecryptRecipients(sk1, bytes.NewReader(cipher.Bytes()), &plain)
	if err != nil {
		panic(err)
	}
	fmt.Println("recipient1", bytes.Equal(value, plain.Bytes()))
	plain.Reset()
	err = libsodium.StreamDecryptRecipients(sk2, bytes.NewReader(cipher.Bytes()), &plain)
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