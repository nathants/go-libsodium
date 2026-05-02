package libsodium

// #cgo CFLAGS: -O3
// #cgo pkg-config: libsodium
// #include <stdlib.h>
// #include <sodium.h>
import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"unsafe"

	"golang.org/x/crypto/blake2b"
)

const (
	maxStreamChunkSize  = 64 * 1024 * 1024
	maxStreamRecipients = 1 << 16
)

var (
	StreamChunkSize = 1024 * 1024
	initDone        = false
)

func validateStreamChunkSize(chunkSize int) error {
	if chunkSize <= 0 || chunkSize > maxStreamChunkSize {
		return fmt.Errorf("bad stream chunk size: %d not in [1, %d]", chunkSize, maxStreamChunkSize)
	}
	return nil
}

func writeFull(w io.Writer, buf []byte) error {
	total := 0
	for total < len(buf) {
		n, err := w.Write(buf[total:])
		if err != nil {
			return err
		} else if n == 0 {
			panic("zero byte write without error")
		}
		total += n
	}
	return nil
}

func Init() {
	if initDone {
		return
	}
	if int(C.sodium_init()) != 0 {
		panic("failed to init sodium")
	}
	initDone = true
}

func StreamKeygen() (key []byte, err error) {
	if !initDone {
		return nil, fmt.Errorf("forgot to init sodium")
	}
	key = make([]byte, C.crypto_secretstream_xchacha20poly1305_KEYBYTES)
	C.crypto_secretstream_xchacha20poly1305_keygen((*C.uchar)(&key[0]))
	return key, nil
}

func validateStreamEncrypt(key []byte, chunkSize int) (int, error) {
	if !initDone {
		return 0, fmt.Errorf("forgot to init sodium")
	}
	if len(key) != C.crypto_secretstream_xchacha20poly1305_KEYBYTES {
		return 0, fmt.Errorf("secretkey bad length: %d != %d", len(key), C.crypto_secretstream_xchacha20poly1305_KEYBYTES)
	}
	if err := validateStreamChunkSize(chunkSize); err != nil {
		return 0, err
	}
	return chunkSize, nil
}

func StreamEncrypt(key []byte, plainText io.Reader, cipherText io.Writer) error {
	streamChunkSize, err := validateStreamEncrypt(key, StreamChunkSize)
	if err != nil {
		return err
	}
	return streamEncrypt(key, streamChunkSize, plainText, cipherText)
}

func streamEncrypt(key []byte, streamChunkSize int, plainText io.Reader, cipherText io.Writer) error {
	header := make([]byte, int(C.crypto_secretstream_xchacha20poly1305_HEADERBYTES))
	var state C.crypto_secretstream_xchacha20poly1305_state
	res := int(C.crypto_secretstream_xchacha20poly1305_init_push(
		&state,
		(*C.uchar)(&header[0]),
		(*C.uchar)(&key[0])),
	)
	if res != 0 {
		return fmt.Errorf("stream init push failed: %d", res)
	}
	err := writeFull(cipherText, header)
	if err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	plainChunk := make([]byte, streamChunkSize)
	for {
		plainChunkSize, err := plainText.Read(plainChunk)
		tag := 0
		if err != nil {
			if err != io.EOF {
				return fmt.Errorf("failed to read plain text: %w", err)
			}
			tag = int(C.crypto_secretstream_xchacha20poly1305_TAG_FINAL)
		}
		cipherChunkSize := uint64(C.crypto_secretstream_xchacha20poly1305_ABYTES + plainChunkSize)
		cipherChunk := make([]byte, cipherChunkSize)
		res := int(C.crypto_secretstream_xchacha20poly1305_push(
			&state,
			(*C.uchar)(&cipherChunk[0]),
			(*C.ulonglong)(&cipherChunkSize),
			(*C.uchar)(&plainChunk[0]),
			(C.ulonglong)(plainChunkSize),
			(*C.uchar)(nil),
			(C.ulonglong)(0),
			(C.uchar)(tag),
		))
		if cipherChunkSize != uint64(C.crypto_secretstream_xchacha20poly1305_ABYTES+plainChunkSize) {
			panic("invalid push")
		}
		if res != 0 {
			return fmt.Errorf("stream push failed: %d", res)
		}
		size := make([]byte, 4)
		binary.LittleEndian.PutUint32(size, uint32(cipherChunkSize))
		err = writeFull(cipherText, size)
		if err != nil {
			return fmt.Errorf("failed to write cipher text length: %w", err)
		}
		err = writeFull(cipherText, cipherChunk)
		if err != nil {
			return fmt.Errorf("failed to write cipher text: %w", err)
		}
		if tag != 0 {
			return nil
		}
	}
}

func StreamDecrypt(key []byte, cipherText io.Reader, plainText io.Writer) error {
	if !initDone {
		panic("forgot to init sodium")
	}
	if len(key) != C.crypto_secretstream_xchacha20poly1305_KEYBYTES {
		return fmt.Errorf("bad stream key length: %d != %d", len(key), C.crypto_secretstream_xchacha20poly1305_KEYBYTES)
	}
	var state C.crypto_secretstream_xchacha20poly1305_state
	header := make([]byte, int(C.crypto_secretstream_xchacha20poly1305_HEADERBYTES))
	_, err := io.ReadFull(cipherText, header)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	res := int(C.crypto_secretstream_xchacha20poly1305_init_pull(
		&state,
		(*C.uchar)(&header[0]),
		(*C.uchar)(&key[0])),
	)
	if res != 0 {
		return fmt.Errorf("stream init pull failed: %d", res)
	}
	for {
		size := make([]byte, 4)
		_, err := io.ReadFull(cipherText, size)
		if err != nil {
			return fmt.Errorf("failed to read cipher text length: %w", err)
		}
		cipherChunkSize := binary.LittleEndian.Uint32(size)
		minCipherChunkSize := uint32(C.crypto_secretstream_xchacha20poly1305_ABYTES)
		maxCipherChunkSize := minCipherChunkSize + uint32(maxStreamChunkSize)
		if cipherChunkSize < minCipherChunkSize || cipherChunkSize > maxCipherChunkSize {
			return fmt.Errorf("bad stream cipher text chunk length: %d not in [%d, %d]", cipherChunkSize, minCipherChunkSize, maxCipherChunkSize)
		}
		cipherChunk := make([]byte, int(cipherChunkSize))
		_, err = io.ReadFull(cipherText, cipherChunk)
		if err != nil {
			return fmt.Errorf("failed to read cipher text: %w", err)
		}
		plainChunkSize := uint64(cipherChunkSize - minCipherChunkSize)
		plainChunk := make([]byte, int(plainChunkSize))
		var tag C.uchar
		var plainChunkPointer *C.uchar
		if plainChunkSize > 0 {
			plainChunkPointer = (*C.uchar)(&plainChunk[0]) // the chunk tagged final can be empty
		}
		res := int(C.crypto_secretstream_xchacha20poly1305_pull(
			&state,
			(*C.uchar)(plainChunkPointer),
			(*C.ulonglong)(&plainChunkSize),
			&tag,
			(*C.uchar)(&cipherChunk[0]),
			(C.ulonglong)(cipherChunkSize),
			(*C.uchar)(nil),
			(C.ulonglong)(0)),
		)
		if res != 0 {
			return fmt.Errorf("stream pull failed: %d", res)
		}
		if plainChunkSize != uint64(cipherChunkSize-minCipherChunkSize) {
			panic("invalid pull")
		}
		err = writeFull(plainText, plainChunk)
		if err != nil {
			return fmt.Errorf("failed to write plain text: %w", err)
		}
		if tag == C.crypto_secretstream_xchacha20poly1305_TAG_FINAL {
			return nil
		}
	}
}

func StreamEncryptRecipients(publicKeys [][]byte, plainText io.Reader, cipherText io.Writer) error {
	streamChunkSize, err := validateStreamEncryptRecipients(publicKeys, StreamChunkSize)
	if err != nil {
		return err
	}
	key := make([]byte, C.crypto_secretstream_xchacha20poly1305_KEYBYTES)
	C.crypto_secretstream_xchacha20poly1305_keygen((*C.uchar)(&key[0]))
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(publicKeys)))
	err = writeFull(cipherText, size)
	if err != nil {
		return err
	}
	for _, publicKey := range publicKeys {
		publicKeyHash := blake2b.Sum512(publicKey)
		keyCipherText, err := BoxSealedEncrypt(key, publicKey)
		if err != nil {
			return err
		}
		keyCipherText = append(publicKeyHash[:], keyCipherText...)
		size := make([]byte, 4)
		binary.LittleEndian.PutUint32(size, uint32(len(keyCipherText)))
		err = writeFull(cipherText, size)
		if err != nil {
			return fmt.Errorf("failed to write cipher text length: %w", err)
		}
		err = writeFull(cipherText, keyCipherText)
		if err != nil {
			return fmt.Errorf("failed to write cipher text: %w", err)
		}
	}
	return streamEncrypt(key, streamChunkSize, plainText, cipherText)
}

func validateStreamEncryptRecipients(publicKeys [][]byte, chunkSize int) (int, error) {
	if !initDone {
		return 0, fmt.Errorf("forgot to init sodium")
	}
	if len(publicKeys) == 0 || len(publicKeys) > maxStreamRecipients {
		return 0, fmt.Errorf("bad stream recipient count: %d not in [1, %d]", len(publicKeys), maxStreamRecipients)
	}
	for _, publicKey := range publicKeys {
		if len(publicKey) != C.crypto_box_PUBLICKEYBYTES {
			return 0, fmt.Errorf("publickey bad length: %d != %d", len(publicKey), C.crypto_box_PUBLICKEYBYTES)
		}
	}
	if err := validateStreamChunkSize(chunkSize); err != nil {
		return 0, err
	}
	return chunkSize, nil
}

func StreamDecryptRecipients(secretKey []byte, cipherText io.Reader, plainText io.Writer) error {
	if !initDone {
		return fmt.Errorf("forgot to init sodium")
	}
	if len(secretKey) != C.crypto_box_SECRETKEYBYTES {
		return fmt.Errorf("secretkey bad length: %d != %d", len(secretKey), C.crypto_box_SECRETKEYBYTES)
	}
	size := make([]byte, 4)
	_, err := io.ReadFull(cipherText, size)
	if err != nil {
		return fmt.Errorf("failed to read num recipients: %w", err)
	}
	numRecipients := binary.LittleEndian.Uint32(size)
	if numRecipients == 0 || numRecipients > maxStreamRecipients {
		return fmt.Errorf("bad stream recipient count: %d not in [1, %d]", numRecipients, maxStreamRecipients)
	}
	publicKey := make([]byte, len(secretKey))
	res := int(C.crypto_scalarmult_base(
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&secretKey[0]),
	))
	if res != 0 {
		return fmt.Errorf("failed to derive publickey from secretkey: %d", res)
	}
	publicKeyHash := blake2b.Sum512(publicKey)
	expectedRecipientRecordSize := uint32(len(publicKeyHash)) + uint32(C.crypto_box_SEALBYTES) + uint32(C.crypto_secretstream_xchacha20poly1305_KEYBYTES)
	var key []byte
	for i := 0; i < int(numRecipients); i++ {
		size := make([]byte, 4)
		_, err := io.ReadFull(cipherText, size)
		if err != nil {
			return fmt.Errorf("failed to read bytes for cipher text length: %w", err)
		}
		keyCipherTextSize := binary.LittleEndian.Uint32(size)
		if keyCipherTextSize != expectedRecipientRecordSize {
			return fmt.Errorf("bad stream recipient record length: %d != %d", keyCipherTextSize, expectedRecipientRecordSize)
		}
		keyCipherText := make([]byte, keyCipherTextSize)
		_, err = io.ReadFull(cipherText, keyCipherText)
		if err != nil {
			return fmt.Errorf("failed to read bytes for cipher text: %w", err)
		}
		recipientPublicKeyHash := keyCipherText[:len(publicKeyHash)]
		keyCipherText = keyCipherText[len(publicKeyHash):]
		if bytes.Equal(publicKeyHash[:], recipientPublicKeyHash) {
			key, err = BoxSealedDecrypt(keyCipherText, secretKey)
			if err != nil {
				return err
			}
		}
	}
	if len(key) == 0 {
		return fmt.Errorf("no recipient matched secret key")
	}
	return StreamDecrypt(key, cipherText, plainText)
}

func BoxKeypair() (publicKey, secretKey []byte, err error) {
	if !initDone {
		return nil, nil, fmt.Errorf("forgot to init sodium")
	}
	publicKey = make([]byte, C.crypto_box_PUBLICKEYBYTES)
	secretKey = make([]byte, C.crypto_box_SECRETKEYBYTES)
	C.crypto_box_keypair(
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&secretKey[0]),
	)
	return publicKey, secretKey, nil
}

func BoxSealedEncrypt(plainText, recipientPublicKey []byte) (cipherText []byte, err error) {
	if !initDone {
		return nil, fmt.Errorf("forgot to init sodium")
	}
	if len(recipientPublicKey) != C.crypto_box_PUBLICKEYBYTES {
		return nil, fmt.Errorf("public key bad length: %d != %d", len(recipientPublicKey), C.crypto_box_PUBLICKEYBYTES)
	}
	cipherTextLen := int(C.crypto_box_SEALBYTES) + len(plainText)
	cipherText = make([]byte, cipherTextLen)
	var plainTextPointer *C.uchar
	if len(plainText) > 0 {
		plainTextPointer = (*C.uchar)(&plainText[0])
	}
	res := int(C.crypto_box_seal(
		(*C.uchar)(&cipherText[0]),
		plainTextPointer,
		(C.ulonglong)(len(plainText)),
		(*C.uchar)(&recipientPublicKey[0]),
	))
	if res != 0 {
		return nil, fmt.Errorf("failed to encrypt: %d", res)
	}
	return cipherText, nil
}

func BoxSealedDecrypt(cipherText, recipientSecretKey []byte) (plainText []byte, err error) {
	if !initDone {
		return nil, fmt.Errorf("forgot to init sodium")
	}
	if len(recipientSecretKey) != C.crypto_box_SECRETKEYBYTES {
		return nil, fmt.Errorf("secret key bad length: %d != %d", len(recipientSecretKey), C.crypto_box_SECRETKEYBYTES)
	}
	if len(cipherText) < int(C.crypto_box_SEALBYTES) {
		return nil, fmt.Errorf("cipher text bad length: %d < %d", len(cipherText), C.crypto_box_SEALBYTES)
	}
	publicKey := make([]byte, len(recipientSecretKey))
	res := int(C.crypto_scalarmult_base(
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&recipientSecretKey[0]),
	))
	if res != 0 {
		return nil, fmt.Errorf("scalar mult failed: %d", res)
	}
	plainTextLen := len(cipherText) - int(C.crypto_box_SEALBYTES)
	plainText = make([]byte, plainTextLen)
	plainTextForC := plainText
	if len(plainTextForC) == 0 {
		plainTextForC = make([]byte, 1)
	}
	res = int(C.crypto_box_seal_open(
		(*C.uchar)(&plainTextForC[0]),
		(*C.uchar)(&cipherText[0]),
		(C.ulonglong)(len(cipherText)),
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&recipientSecretKey[0]),
	))
	if res != 0 {
		return nil, fmt.Errorf("failed to decrypt: %d", res)
	}
	return plainText, nil
}

func BoxEasyEncrypt(plainText, recipientPublicKey, senderSecretKey []byte) (cipherText []byte, err error) {
	if !initDone {
		return nil, fmt.Errorf("forgot to init sodium")
	}
	if len(recipientPublicKey) != C.crypto_box_PUBLICKEYBYTES {
		return nil, fmt.Errorf("public key bad length: %d != %d", len(recipientPublicKey), C.crypto_box_PUBLICKEYBYTES)
	}
	if len(senderSecretKey) != C.crypto_box_SECRETKEYBYTES {
		return nil, fmt.Errorf("secret key bad length: %d != %d", len(senderSecretKey), C.crypto_box_SECRETKEYBYTES)
	}
	cipherTextLen := int(C.crypto_box_NONCEBYTES) + int(C.crypto_box_MACBYTES) + len(plainText)
	cipherText = make([]byte, cipherTextLen)
	C.randombytes_buf(
		unsafe.Pointer(&cipherText[0]),
		C.crypto_box_NONCEBYTES,
	)
	var plainTextPointer *C.uchar
	if len(plainText) > 0 {
		plainTextPointer = (*C.uchar)(&plainText[0])
	}
	res := int(C.crypto_box_easy(
		(*C.uchar)(&cipherText[int(C.crypto_box_NONCEBYTES)]),
		plainTextPointer,
		(C.ulonglong)(len(plainText)),
		(*C.uchar)(&cipherText[0]),
		(*C.uchar)(&recipientPublicKey[0]),
		(*C.uchar)(&senderSecretKey[0]),
	))
	if res != 0 {
		return nil, fmt.Errorf("encryption failed: %d", res)
	}
	return cipherText, nil
}

func BoxEasyDecrypt(cipherText, senderPublicKey, recipientSecretKey []byte) (plainText []byte, err error) {
	if !initDone {
		return nil, fmt.Errorf("forgot to init sodium")
	}
	if len(senderPublicKey) != C.crypto_box_PUBLICKEYBYTES {
		return nil, fmt.Errorf("public key bad length: %d != %d", len(senderPublicKey), C.crypto_box_PUBLICKEYBYTES)
	}
	if len(recipientSecretKey) != C.crypto_box_SECRETKEYBYTES {
		return nil, fmt.Errorf("secret key bad length: %d != %d", len(recipientSecretKey), C.crypto_box_SECRETKEYBYTES)
	}
	minCipherTextLen := int(C.crypto_box_MACBYTES) + int(C.crypto_box_NONCEBYTES)
	if len(cipherText) < minCipherTextLen {
		return nil, fmt.Errorf("cipher text bad length: %d < %d", len(cipherText), minCipherTextLen)
	}
	plainTextLen := len(cipherText) - minCipherTextLen
	plainText = make([]byte, plainTextLen)
	plainTextForC := plainText
	if len(plainTextForC) == 0 {
		plainTextForC = make([]byte, 1)
	}
	res := int(C.crypto_box_open_easy(
		(*C.uchar)(&plainTextForC[0]),
		(*C.uchar)(&cipherText[int(C.crypto_box_NONCEBYTES)]),
		(C.ulonglong)(len(cipherText[int(C.crypto_box_NONCEBYTES):])),
		(*C.uchar)(&cipherText[0]),
		(*C.uchar)(&senderPublicKey[0]),
		(*C.uchar)(&recipientSecretKey[0]),
	))
	if res != 0 {
		return nil, fmt.Errorf("decryption failed: %d", res)
	}
	return plainText, nil
}

func SignKeypair() (publicKey, secretKey []byte, err error) {
	if !initDone {
		return nil, nil, fmt.Errorf("forgot to init sodium")
	}
	publicKey = make([]byte, C.crypto_sign_PUBLICKEYBYTES)
	secretKey = make([]byte, C.crypto_sign_SECRETKEYBYTES)
	C.crypto_sign_keypair(
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&secretKey[0]),
	)
	return publicKey, secretKey, nil
}

func Sign(plainText, signerSecretKey []byte) (signedText []byte, err error) {
	if !initDone {
		return nil, fmt.Errorf("forgot to init sodium")
	}
	if len(signerSecretKey) != C.crypto_sign_SECRETKEYBYTES {
		return nil, fmt.Errorf("secret key bad length: %d != %d", len(signerSecretKey), C.crypto_sign_SECRETKEYBYTES)
	}
	signedTextLen := uint64(int(C.crypto_sign_BYTES) + len(plainText))
	signedText = make([]byte, signedTextLen)
	var plainTextPointer *C.uchar
	if len(plainText) > 0 {
		plainTextPointer = (*C.uchar)(&plainText[0])
	}
	res := int(C.crypto_sign(
		(*C.uchar)(&signedText[0]),
		(*C.ulonglong)(&signedTextLen),
		plainTextPointer,
		(C.ulonglong)(len(plainText)),
		(*C.uchar)(&signerSecretKey[0]),
	))
	if res != 0 {
		return nil, fmt.Errorf("sign failed: %d", res)
	}
	return signedText, nil
}

func SignVerify(signedText, plainText, signerPublicKey []byte) error {
	if !initDone {
		return fmt.Errorf("forgot to init sodium")
	}
	if len(signerPublicKey) != C.crypto_sign_PUBLICKEYBYTES {
		return fmt.Errorf("public key bad length: %d != %d", len(signerPublicKey), C.crypto_sign_PUBLICKEYBYTES)
	}
	if len(signedText) < int(C.crypto_sign_BYTES) {
		return fmt.Errorf("signed text bad length: %d < %d", len(signedText), C.crypto_sign_BYTES)
	}
	expectedPlainTextLen := len(signedText) - int(C.crypto_sign_BYTES)
	if expectedPlainTextLen != len(plainText) {
		return fmt.Errorf("sign verify failed: plaintext length mismatch")
	}
	openedPlainText := make([]byte, expectedPlainTextLen)
	if len(openedPlainText) == 0 {
		openedPlainText = make([]byte, 1)
	}
	openedPlainTextLen := uint64(0)
	signedTextLen := uint64(len(signedText))
	res := int(C.crypto_sign_open(
		(*C.uchar)(&openedPlainText[0]),
		(*C.ulonglong)(&openedPlainTextLen),
		(*C.uchar)(&signedText[0]),
		(C.ulonglong)(signedTextLen),
		(*C.uchar)(&signerPublicKey[0]),
	))
	if res != 0 {
		return fmt.Errorf("sign verify failed: %d", res)
	}
	if openedPlainTextLen != uint64(expectedPlainTextLen) {
		return fmt.Errorf("sign verify failed: opened plaintext length %d != %d", openedPlainTextLen, expectedPlainTextLen)
	}
	openedPlainText = openedPlainText[:expectedPlainTextLen]
	if !bytes.Equal(openedPlainText, plainText) {
		return fmt.Errorf("sign verify failed: plaintext mismatch")
	}
	return nil
}
