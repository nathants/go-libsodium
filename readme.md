# go-libsodium

## why

using libsodium should be easy.

## how

a minimal cgo interface to the following libsodium constructs:

- [crypt_box_easy](https://doc.libsodium.org/secret-key_cryptography/secretbox)

- [crypto_box_seal](https://doc.libsodium.org/public-key_cryptography/sealed_boxes)

- [crypto_sign](https://doc.libsodium.org/public-key_cryptography/public-key_signatures)

- [crypto_stream](https://doc.libsodium.org/secret-key_cryptography/secretstream)

## what

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

## install

```bash
sudo apt-get install -y libsodium-dev # ubuntu/debian
sudo apk add libsodium-dev            # alpine
sudo pacman -S libsodium              # arch
```

```bash
go get github.com/nathants/libsodium
```

## usage

```go
```
