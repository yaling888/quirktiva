package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/yaling888/quirktiva/common/pool"
)

var ErrInvalidCiphertext = errors.New("invalid ciphertext")

type AEAD struct {
	cipher.AEAD
}

func (a *AEAD) Encrypt(dst *pool.BufferWriter, plaintext []byte) ([]byte, error) {
	offset := dst.Len()

	dst.Grow(a.NonceSize() + a.Overhead() + len(plaintext))

	nonce := (*dst)[offset : offset+a.NonceSize()]
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	b := a.Seal((*dst)[offset:offset+a.NonceSize()], nonce, plaintext, nil)
	*dst = (*dst)[:offset+len(b)]
	return b, nil
}

func (a *AEAD) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) <= a.NonceSize() {
		return nil, ErrInvalidCiphertext
	}

	nonce := ciphertext[:a.NonceSize()]
	payload := ciphertext[a.NonceSize():]

	b, err := a.Open(ciphertext[a.NonceSize():a.NonceSize()], nonce, payload, nil)
	if err != nil {
		return nil, ErrInvalidCiphertext
	}

	return ciphertext[a.NonceSize() : a.NonceSize()+len(b)], nil
}

func (a *AEAD) Clone() *AEAD {
	o := *a
	v := new(AEAD)
	*v = o
	return v
}

// NewAEAD supports security "none" | "aes-128-gcm" | "chacha20-poly1305",
// returns "nil, nil" if security is "none"
func NewAEAD(security, key, salt string) (*AEAD, error) {
	security = strings.ToLower(security)
	if security == "" || security == "none" {
		return nil, nil
	}

	salted := []byte(key + salt)
	keySum := sha256.Sum256(salted)

	var (
		aead cipher.AEAD
		err  error
	)
	switch security {
	case "aes-128-gcm":
		var block cipher.Block
		block, err = aes.NewCipher(keySum[:16])
		if err != nil {
			return nil, err
		}
		aead, err = cipher.NewGCM(block)
	case "chacha20-poly1305":
		aead, err = chacha20poly1305.New(keySum[:])
	default:
		err = fmt.Errorf("unsupported cipher: %s", security)
	}

	if err != nil {
		return nil, err
	}

	return &AEAD{AEAD: aead}, nil
}
