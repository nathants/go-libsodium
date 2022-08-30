package libsodium

import (
	"bytes"
	"testing"
)

func TestStream(t *testing.T) {
	StreamChunkSize = 2
	Init()
	key, err := StreamKeygen()
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("hello world")
	var cipher bytes.Buffer
	err = StreamEncrypt(key, bytes.NewReader(value), &cipher)
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	err = StreamDecrypt(key, bytes.NewReader(cipher.Bytes()), &plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, plain.Bytes()) {
		t.Fatal("fail")
	}
}

func TestStreamRecipients(t *testing.T) {
	StreamChunkSize = 2
	Init()
	pk1, sk1, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pk2, sk2, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("hello world")
	var cipher bytes.Buffer
	err = StreamEncryptRecipients([][]byte{pk1, pk2}, bytes.NewReader(value), &cipher)
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	err = StreamDecryptRecipients(sk1, bytes.NewReader(cipher.Bytes()), &plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, plain.Bytes()) {
		t.Fatal("sk1 failed")
	}
	plain.Reset()
	err = StreamDecryptRecipients(sk2, bytes.NewReader(cipher.Bytes()), &plain)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, plain.Bytes()) {
		t.Fatal("sk2 failed")
	}
}

func TestBoxSeal(t *testing.T) {
	Init()
	value := []byte("hello world")
	pk, sk, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := BoxSealedEncrypt(value, pk)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := BoxSealedDecrypt(cipher, sk)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, plain) {
		t.Fatal("sk failure")
	}
}

func TestBoxEasy(t *testing.T) {
	Init()
	value := []byte("hello world")
	pk1, sk1, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	pk2, sk2, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := BoxEasyEncrypt(value, pk2, sk1)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := BoxEasyDecrypt(cipher, pk1, sk2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(value, plain) {
		t.Fatal("sk failure")
	}
}

func TestSign(t *testing.T) {
	Init()
	value := []byte("hello world")
	pk, sk, err := SignKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signature, err := Sign(value, sk)
	if err != nil {
		t.Fatal(err)
	}
	err = SignVerify(signature, value, pk)
	if err != nil {
		t.Fatal(err)
	}
}
