package libsodium

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"strings"
	"testing"
)

const secretstreamHeaderBytes = 24

type payloadRejectingReader struct {
	data        []byte
	payloadRead bool
}

func (r *payloadRejectingReader) Read(p []byte) (int, error) {
	if len(r.data) > 0 {
		n := copy(p, r.data)
		r.data = r.data[n:]
		return n, nil
	}
	if len(p) == 0 {
		return 0, nil
	}
	r.payloadRead = true
	return 0, io.EOF
}

func streamHeaderAndABYTES(t *testing.T, key []byte) ([]byte, int) {
	t.Helper()

	var emptyCipher bytes.Buffer
	if err := StreamEncrypt(key, bytes.NewReader(nil), &emptyCipher); err != nil {
		t.Fatal(err)
	}
	var oneByteCipher bytes.Buffer
	if err := StreamEncrypt(key, bytes.NewReader([]byte{0}), &oneByteCipher); err != nil {
		t.Fatal(err)
	}

	abytes := oneByteCipher.Len() - emptyCipher.Len() - 5
	if abytes <= 0 {
		t.Fatalf("invalid stream ABYTES inferred from ciphertext lengths: %d", abytes)
	}
	headerLen := emptyCipher.Len() - 4 - abytes
	if headerLen <= 0 || headerLen > emptyCipher.Len() {
		t.Fatalf("invalid stream header length inferred from ciphertext lengths: %d", headerLen)
	}
	return append([]byte(nil), emptyCipher.Bytes()[:headerLen]...), abytes
}

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

func TestStreamDecryptRejectsInvalidChunkLengths(t *testing.T) {
	Init()
	oldChunkSize := StreamChunkSize
	StreamChunkSize = 2
	defer func() { StreamChunkSize = oldChunkSize }()

	key, err := StreamKeygen()
	if err != nil {
		t.Fatal(err)
	}
	header, abytes := streamHeaderAndABYTES(t, key)

	tests := []struct {
		name            string
		chunkSize       uint32
		wantPayloadRead bool
	}{
		{
			name:            "below abytes",
			chunkSize:       uint32(abytes - 1),
			wantPayloadRead: false,
		},
		{
			name:            "above max chunk size",
			chunkSize:       uint32(abytes + maxStreamChunkSize + 1),
			wantPayloadRead: false,
		},
		{
			name:            "valid length still reads payload",
			chunkSize:       uint32(abytes),
			wantPayloadRead: true,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := append([]byte(nil), header...)
			input = binary.LittleEndian.AppendUint32(input, test.chunkSize)
			reader := &payloadRejectingReader{data: input}

			err := StreamDecrypt(key, reader, io.Discard)
			if err == nil {
				t.Fatal("should have failed")
			}
			if test.wantPayloadRead != reader.payloadRead {
				t.Fatalf("payload read = %t, want %t", reader.payloadRead, test.wantPayloadRead)
			}
			if !test.wantPayloadRead && !strings.Contains(err.Error(), "bad stream cipher text chunk length") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestStreamEncryptUsesExistingWireFormat(t *testing.T) {
	Init()
	oldChunkSize := StreamChunkSize
	StreamChunkSize = 4
	defer func() { StreamChunkSize = oldChunkSize }()

	key, err := StreamKeygen()
	if err != nil {
		t.Fatal(err)
	}
	header, abytes := streamHeaderAndABYTES(t, key)
	if len(header) != secretstreamHeaderBytes {
		t.Fatalf("stream header length = %d, want %d", len(header), secretstreamHeaderBytes)
	}

	value := []byte("abcd")
	var cipher bytes.Buffer
	if err := StreamEncrypt(key, bytes.NewReader(value), &cipher); err != nil {
		t.Fatal(err)
	}
	if cipher.Len() < len(header)+4 {
		t.Fatalf("cipher text too short: %d", cipher.Len())
	}
	firstChunkSize := binary.LittleEndian.Uint32(cipher.Bytes()[len(header) : len(header)+4])
	wantFirstChunkSize := uint32(abytes + len(value))
	if firstChunkSize != wantFirstChunkSize {
		t.Fatalf("first chunk size = %d, want %d", firstChunkSize, wantFirstChunkSize)
	}
}

func TestStreamDecryptReadsExistingWireFormat(t *testing.T) {
	Init()
	oldChunkSize := StreamChunkSize
	StreamChunkSize = 1
	defer func() { StreamChunkSize = oldChunkSize }()

	key, err := hex.DecodeString("0707070707070707070707070707070707070707070707070707070707070707")
	if err != nil {
		t.Fatal(err)
	}
	cipher, err := hex.DecodeString("f4c4a41edcd3ab6ca46c4edf746fad0c7914485a5098aa941300000036d8110093848669440183fb92dd934278089f13000000cc3f21377ffb8b59c3d21d4291e44b5693b12c13000000bfdb98eefb928e4de3528867e13661a214732713000000c6086679e15a42408df1ad948b1066363c025c130000002bbee6b8530a5e21c5753884a03caaef03652912000000f5edd2b7e52c79d2b1766fcd67aafec091b71100000050d3c6e6b8ceb72a138f9f48ebfb76a3c5")
	if err != nil {
		t.Fatal(err)
	}
	var plain bytes.Buffer
	if err := StreamDecrypt(key, bytes.NewReader(cipher), &plain); err != nil {
		t.Fatal(err)
	}
	wantPlain := []byte("hello world")
	if !bytes.Equal(plain.Bytes(), wantPlain) {
		t.Fatalf("plain text = %q, want %q", plain.Bytes(), wantPlain)
	}
}

func TestStreamEncryptRejectsInvalidChunkSize(t *testing.T) {
	Init()
	oldChunkSize := StreamChunkSize
	defer func() { StreamChunkSize = oldChunkSize }()

	key, err := StreamKeygen()
	if err != nil {
		t.Fatal(err)
	}

	for _, chunkSize := range []int{0, -1, maxStreamChunkSize + 1} {
		t.Run(fmt.Sprintf("%d", chunkSize), func(t *testing.T) {
			StreamChunkSize = chunkSize
			var cipher bytes.Buffer
			err := StreamEncrypt(key, bytes.NewReader([]byte("x")), &cipher)
			if err == nil {
				t.Fatal("should have failed")
			}
			if !strings.Contains(err.Error(), "bad stream chunk size") {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestStreamLarge(t *testing.T) {
	StreamChunkSize = 1024 * 1024
	Init()
	key, err := StreamKeygen()
	if err != nil {
		t.Fatal(err)
	}
	value := []byte("hello world")
	for i := 0; i < 1024*1024*500; i++ {
		value = append(value, ' ')
	}
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

func TestStreamEncryptRecipientsRejectsInvalidRecipientCount(t *testing.T) {
	Init()

	err := StreamEncryptRecipients(nil, bytes.NewReader(nil), io.Discard)
	if err == nil {
		t.Fatal("should have failed")
	}
	if !strings.Contains(err.Error(), "bad stream recipient count") {
		t.Fatalf("unexpected error: %v", err)
	}

	err = StreamEncryptRecipients(make([][]byte, maxStreamRecipients+1), bytes.NewReader(nil), io.Discard)
	if err == nil {
		t.Fatal("should have failed")
	}
	if !strings.Contains(err.Error(), "bad stream recipient count") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestStreamEncryptRecipientsRejectsLocalValidationErrorsWithoutWriting(t *testing.T) {
	Init()
	pk, _, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}

	oldChunkSize := StreamChunkSize
	defer func() { StreamChunkSize = oldChunkSize }()
	StreamChunkSize = 0
	var invalidChunkCipher bytes.Buffer
	err = StreamEncryptRecipients([][]byte{pk}, bytes.NewReader(nil), &invalidChunkCipher)
	if err == nil {
		t.Fatal("should have failed")
	}
	if !strings.Contains(err.Error(), "bad stream chunk size") {
		t.Fatalf("unexpected error: %v", err)
	}
	if invalidChunkCipher.Len() != 0 {
		t.Fatalf("wrote %d bytes before rejecting invalid chunk size", invalidChunkCipher.Len())
	}

	oldInitDone := initDone
	defer func() { initDone = oldInitDone }()
	StreamChunkSize = oldChunkSize
	initDone = false
	var notInitializedCipher bytes.Buffer
	err = StreamEncryptRecipients([][]byte{pk}, bytes.NewReader(nil), &notInitializedCipher)
	if err == nil {
		t.Fatal("should have failed")
	}
	if !strings.Contains(err.Error(), "forgot to init sodium") {
		t.Fatalf("unexpected error: %v", err)
	}
	if notInitializedCipher.Len() != 0 {
		t.Fatalf("wrote %d bytes before rejecting missing init", notInitializedCipher.Len())
	}
}

func TestStreamDecryptRecipientsRejectsMissingInitWithoutReading(t *testing.T) {
	Init()
	_, sk, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}

	oldInitDone := initDone
	initDone = false
	defer func() { initDone = oldInitDone }()

	reader := &payloadRejectingReader{}
	err = StreamDecryptRecipients(sk, reader, io.Discard)
	if err == nil {
		t.Fatal("should have failed")
	}
	if !strings.Contains(err.Error(), "forgot to init sodium") {
		t.Fatalf("unexpected error: %v", err)
	}
	if reader.payloadRead {
		t.Fatal("read cipher text before rejecting missing init")
	}
}

func TestStreamDecryptRecipientsRejectsInvalidRecipientMetadata(t *testing.T) {
	Init()
	pk, sk, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	var validCipher bytes.Buffer
	if err := StreamEncryptRecipients([][]byte{pk}, bytes.NewReader(nil), &validCipher); err != nil {
		t.Fatal(err)
	}
	validCipherText := validCipher.Bytes()
	if len(validCipherText) < 8 {
		t.Fatalf("recipient ciphertext too short: %d", len(validCipherText))
	}
	validRecordSize := binary.LittleEndian.Uint32(validCipherText[4:8])

	tests := []struct {
		name            string
		input           []byte
		wantPayloadRead bool
		wantErr         string
	}{
		{
			name:    "zero recipients",
			input:   binary.LittleEndian.AppendUint32(nil, 0),
			wantErr: "bad stream recipient count",
		},
		{
			name:    "too many recipients",
			input:   binary.LittleEndian.AppendUint32(nil, uint32(maxStreamRecipients+1)),
			wantErr: "bad stream recipient count",
		},
		{
			name:    "short record",
			input:   binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, 1), 63),
			wantErr: "bad stream recipient record length",
		},
		{
			name:    "oversized record",
			input:   binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, 1), ^uint32(0)),
			wantErr: "bad stream recipient record length",
		},
		{
			name:            "valid record length reads record",
			input:           binary.LittleEndian.AppendUint32(binary.LittleEndian.AppendUint32(nil, 1), validRecordSize),
			wantPayloadRead: true,
			wantErr:         "failed to read bytes for cipher text",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			reader := &payloadRejectingReader{data: append([]byte(nil), test.input...)}

			err := StreamDecryptRecipients(sk, reader, io.Discard)
			if err == nil {
				t.Fatal("should have failed")
			}
			if !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("unexpected error: %v", err)
			}
			if test.wantPayloadRead != reader.payloadRead {
				t.Fatalf("payload read = %t, want %t", reader.payloadRead, test.wantPayloadRead)
			}
		})
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

func TestByteSliceCryptoWrappersHandleEmptyMessages(t *testing.T) {
	Init()

	sealedPublicKey, sealedSecretKey, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	senderPublicKey, senderSecretKey, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientPublicKey, recipientSecretKey, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	signerPublicKey, signerSecretKey, err := SignKeypair()
	if err != nil {
		t.Fatal(err)
	}

	for _, test := range []struct {
		name    string
		message []byte
	}{
		{name: "nil", message: nil},
		{name: "empty", message: []byte{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			sealedCipherText, err := BoxSealedEncrypt(test.message, sealedPublicKey)
			if err != nil {
				t.Fatal(err)
			}
			sealedPlainText, err := BoxSealedDecrypt(sealedCipherText, sealedSecretKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(sealedPlainText, test.message) {
				t.Fatalf("sealed plaintext = %q, want %q", sealedPlainText, test.message)
			}

			easyCipherText, err := BoxEasyEncrypt(test.message, recipientPublicKey, senderSecretKey)
			if err != nil {
				t.Fatal(err)
			}
			easyPlainText, err := BoxEasyDecrypt(easyCipherText, senderPublicKey, recipientSecretKey)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(easyPlainText, test.message) {
				t.Fatalf("easy plaintext = %q, want %q", easyPlainText, test.message)
			}

			signedText, err := Sign(test.message, signerSecretKey)
			if err != nil {
				t.Fatal(err)
			}
			if err := SignVerify(signedText, test.message, signerPublicKey); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestByteSliceCryptoWrappersRejectShortInputs(t *testing.T) {
	Init()

	boxPublicKey, boxSecretKey, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BoxSealedDecrypt(nil, boxSecretKey); err == nil {
		t.Fatal("empty sealed ciphertext should have failed")
	}
	sealedCipherText, err := BoxSealedEncrypt([]byte("x"), boxPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BoxSealedDecrypt(sealedCipherText[:len(sealedCipherText)-2], boxSecretKey); err == nil {
		t.Fatal("short sealed ciphertext should have failed")
	}

	senderPublicKey, senderSecretKey, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	recipientPublicKey, recipientSecretKey, err := BoxKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BoxEasyDecrypt(nil, senderPublicKey, recipientSecretKey); err == nil {
		t.Fatal("empty easy ciphertext should have failed")
	}
	easyCipherText, err := BoxEasyEncrypt([]byte("x"), recipientPublicKey, senderSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := BoxEasyDecrypt(easyCipherText[:len(easyCipherText)-2], senderPublicKey, recipientSecretKey); err == nil {
		t.Fatal("short easy ciphertext should have failed")
	}

	signerPublicKey, signerSecretKey, err := SignKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err := SignVerify(nil, nil, signerPublicKey); err == nil {
		t.Fatal("empty signed text should have failed")
	}
	signedText, err := Sign([]byte("x"), signerSecretKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := SignVerify(signedText[:len(signedText)-2], nil, signerPublicKey); err == nil {
		t.Fatal("short signed text should have failed")
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
	shortValue := []byte("short")
	err = SignVerify(signature, shortValue, pk)
	if err == nil {
		t.Fatal("should have failed")
	}
	if !bytes.Equal(shortValue, []byte("short")) {
		t.Fatalf("verify mutated plaintext: %q", shortValue)
	}
	differentValue := []byte("HELLO WORLD")
	err = SignVerify(signature, differentValue, pk)
	if err == nil {
		t.Fatal("should have failed")
	}
	if !bytes.Equal(differentValue, []byte("HELLO WORLD")) {
		t.Fatalf("verify mutated plaintext: %q", differentValue)
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
