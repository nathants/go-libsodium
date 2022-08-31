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
	bitflipCipher := append([]byte{}, cipher.Bytes()...)
	bitflipCipher[len(bitflipCipher)/2]++
	err = StreamDecrypt(key, bytes.NewReader(bitflipCipher), &plain)
	if err == nil {
		t.Fatal("should have failed")
	}
	bitflipKey := append([]byte{}, key...)
	bitflipKey[len(bitflipKey)/2]++
	err = StreamDecrypt(bitflipKey, bytes.NewReader(cipher.Bytes()), &plain)
	if err == nil {
		t.Fatal("should have failed")
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
	bitflipCipher := append([]byte{}, cipher.Bytes()...)
	bitflipCipher[len(bitflipCipher)/2]++
	err = StreamDecryptRecipients(sk2, bytes.NewReader(bitflipCipher), &plain)
	if err == nil {
		t.Fatal("should have failed")
	}
	bitflipKey := append([]byte{}, sk2...)
	bitflipKey[len(bitflipKey)/2]++
	err = StreamDecryptRecipients(bitflipKey, bytes.NewReader(cipher.Bytes()), &plain)
	if err == nil {
		t.Fatal("should have failed")
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
	bitflipCipher := append([]byte{}, cipher...)
	bitflipCipher[len(bitflipCipher)/2]++
	_, err = BoxSealedDecrypt(bitflipCipher, sk)
	if err == nil {
		t.Fatal("should have failed")
	}
	bitflipKey := append([]byte{}, sk...)
	bitflipKey[len(bitflipKey)/2]++
	_, err = BoxSealedDecrypt(cipher, bitflipKey)
	if err == nil {
		t.Fatal("should have failed")
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
	bitflipCipher := append([]byte{}, cipher...)
	bitflipCipher[len(bitflipCipher)/2]++
	_, err = BoxEasyDecrypt(bitflipCipher, pk1, sk2)
	if err == nil {
		t.Fatal("should have failed")
	}
	bitflipKey := append([]byte{}, sk2...)
	bitflipKey[len(bitflipKey)/2]++
	_, err = BoxEasyDecrypt(cipher, pk1, bitflipKey)
	if err == nil {
		t.Fatal("should have failed")
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
	bitflipSignature := append([]byte{}, signature...)
	bitflipSignature[len(bitflipSignature)/2]++
	err = SignVerify(bitflipSignature, value, pk)
	if err == nil {
		t.Fatal("should have failed")
	}
	bitflipKey := append([]byte{}, pk...)
	bitflipKey[len(bitflipKey)/2]++
	err = SignVerify(signature, value, bitflipKey)
	if err == nil {
		t.Fatal("should have failed")
	}
}
