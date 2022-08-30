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

var (
	StreamChunkSize = 1024 * 1024
	initDone        = false
)

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

func StreamEncrypt(key []byte, plainText io.Reader, cipherText io.Writer) error {
	if !initDone {
		return fmt.Errorf("forgot to init sodium")
	}
	if len(key) != C.crypto_secretstream_xchacha20poly1305_KEYBYTES {
		return fmt.Errorf("secretkey bad length: %d != %d", len(key), C.crypto_secretstream_xchacha20poly1305_KEYBYTES)
	}
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
	n, err := cipherText.Write(header)
	if err != nil {
		return fmt.Errorf("failed to write header: %w", err)
	}
	if n != len(header) {
		return fmt.Errorf("failed to write enough header bytes: %d != %d", n, len(header))
	}
	plainChunk := make([]byte, StreamChunkSize)
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
		if res != 0 {
			return fmt.Errorf("stream push failed: %d", res)
		}
		size := make([]byte, 4)
		binary.LittleEndian.PutUint32(size, uint32(cipherChunkSize))
		n, err = cipherText.Write(size)
		if err != nil {
			return fmt.Errorf("failed to write cipher text length: %w", err)
		}
		if n != len(size) {
			return fmt.Errorf("failed to write enough bytes for cipher text length: %d != %d", n, len(size))
		}
		n, err = cipherText.Write(cipherChunk)
		if err != nil {
			return fmt.Errorf("failed to write cipher text: %w", err)
		}
		if n != len(cipherChunk) {
			return fmt.Errorf("failed to write enough bytes for cipher text: %d != %d", n, len(cipherChunk))
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
	n, err := cipherText.Read(header)
	if err != nil {
		return fmt.Errorf("failed to read header: %w", err)
	}
	if n != len(header) {
		return fmt.Errorf("failed to read enough bytes for header: %d != %d", n, len(header))
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
		n, err := cipherText.Read(size)
		if n != len(size) {
			return fmt.Errorf("failed to read enough bytes for cipher text length: %d != %d", n, len(size))
		}
		if err != nil {
			return fmt.Errorf("failed to read cipher text length: %w", err)
		}
		cipherChunkSize := binary.LittleEndian.Uint32(size)
		cipherChunk := make([]byte, cipherChunkSize)
		n, err = cipherText.Read(cipherChunk)
		if n != len(cipherChunk) {
			return fmt.Errorf("failed to read enough bytes for cipher text: %d != %d", n, len(cipherChunk))
		}
		if err != nil {
			return fmt.Errorf("failed to read cipher text: %w", err)
		}
		plainChunkSize := uint64(cipherChunkSize - uint32(C.crypto_secretstream_xchacha20poly1305_ABYTES))
		plainChunk := make([]byte, plainChunkSize)
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
		n, err = plainText.Write(plainChunk)
		if err != nil {
			return fmt.Errorf("failed to write plain text: %w", err)
		}
		if n != len(plainChunk) {
			return fmt.Errorf("failed to write enough bytes for plain text: %d != %d", n, len(plainChunk))
		}
		if tag == C.crypto_secretstream_xchacha20poly1305_TAG_FINAL {
			return nil
		}
	}
}

func StreamEncryptRecipients(publicKeys [][]byte, plainText io.Reader, cipherText io.Writer) error {
	for _, publicKey := range publicKeys {
		if len(publicKey) != C.crypto_box_PUBLICKEYBYTES {
			return fmt.Errorf("publickey bad length: %d != %d", len(publicKey), C.crypto_box_PUBLICKEYBYTES)
		}
	}
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(len(publicKeys)))
	n, err := cipherText.Write(size)
	if err != nil {
		panic(err)
	}
	if n != len(size) {
		panic(fmt.Sprintf("%d != %d", n, len(size)))
	}
	key, err := StreamKeygen()
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
		n, err := cipherText.Write(size)
		if err != nil {
			return fmt.Errorf("failed to write cipher text length: %w", err)
		}
		if n != len(size) {
			return fmt.Errorf("failed to write enough bytes for cipher text length: %d != %d", n, len(size))
		}
		n, err = cipherText.Write(keyCipherText)
		if err != nil {
			return fmt.Errorf("failed to write cipher text: %w", err)
		}
		if n != len(keyCipherText) {
			return fmt.Errorf("failed to write enough bytes for cipher text: %d != %d", n, len(keyCipherText))
		}
	}
	return StreamEncrypt(key, plainText, cipherText)
}

func StreamDecryptRecipients(secretKey []byte, cipherText io.Reader, plainText io.Writer) error {
	if len(secretKey) != C.crypto_box_SECRETKEYBYTES {
		return fmt.Errorf("secretkey bad length: %d != %d", len(secretKey), C.crypto_box_SECRETKEYBYTES)
	}
	size := make([]byte, 4)
	n, err := cipherText.Read(size)
	if n != len(size) {
		return fmt.Errorf("failed to read enough bytes for num recipients: %d != %d", n, len(size))
	}
	if err != nil {
		return fmt.Errorf("failed to read num recipients: %w", err)
	}
	publicKey := make([]byte, len(secretKey))
	res := int(C.crypto_scalarmult_base(
		(*C.uchar)(&publicKey[0]),
		(*C.uchar)(&secretKey[0]),
	))
	if res != 0 {
		return fmt.Errorf("failed to derive publickey from secretkey: %d", res)
	}
	numRecipients := binary.LittleEndian.Uint32(size)
	var key []byte
	for i := 0; i < int(numRecipients); i++ {
		size := make([]byte, 4)
		n, err := cipherText.Read(size)
		if n != len(size) {
			return fmt.Errorf("failed to read enough bytes for cipher text length: %d != %d", n, len(size))
		}
		if err != nil {
			return fmt.Errorf("failed to read bytes for cipher text length: %w", err)
		}
		keyCipherTextSize := binary.LittleEndian.Uint32(size)
		keyCipherText := make([]byte, keyCipherTextSize)
		n, err = cipherText.Read(keyCipherText)
		if err != nil {
			return fmt.Errorf("failed to read bytes for cipher text: %w", err)
		}
		if n != len(keyCipherText) {
			return fmt.Errorf("failed to read enough bytes for cipher text: %d != %d", n, len(keyCipherText))
		}
		publicKeyHash := blake2b.Sum512(publicKey)
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
	res := int(C.crypto_box_seal(
		(*C.uchar)(&cipherText[0]),
		(*C.uchar)(&plainText[0]),
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
	res = int(C.crypto_box_seal_open(
		(*C.uchar)(&plainText[0]),
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
	res := int(C.crypto_box_easy(
		(*C.uchar)(&cipherText[int(C.crypto_box_NONCEBYTES)]),
		(*C.uchar)(&plainText[0]),
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
	plainTextLen := len(cipherText) - int(C.crypto_box_MACBYTES) - int(C.crypto_box_NONCEBYTES)
	plainText = make([]byte, plainTextLen)
	res := int(C.crypto_box_open_easy(
		(*C.uchar)(&plainText[0]),
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
	res := int(C.crypto_sign(
		(*C.uchar)(&signedText[0]),
		(*C.ulonglong)(&signedTextLen),
		(*C.uchar)(&plainText[0]),
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
	plainTextLen := uint64(len(plainText))
	signatureTextLen := uint64(len(signedText))
	res := int(C.crypto_sign_open(
		(*C.uchar)(&plainText[0]),
		(*C.ulonglong)(&plainTextLen),
		(*C.uchar)(&signedText[0]),
		(C.ulonglong)(signatureTextLen),
		(*C.uchar)(&signerPublicKey[0]),
	))
	if res != 0 {
		return fmt.Errorf("sign verify failed: %d", res)
	}
	return nil
}
