package crypto

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"io"
)

// PrivateKey ...
type PrivateKey struct {
	hash    []byte
	private *rsa.PrivateKey
	public  *PublicKey
}

// NewPrivateKey ...
func NewPrivateKey(file []byte) (*PrivateKey, error) {
	key, err := parsePrivateKey(file)
	if err != nil {
		return nil, err
	}

	privateHash, err := hash(key)
	if err != nil {
		return nil, err
	}

	publicHash, err := hash(&key.PublicKey)
	if err != nil {
		return nil, err
	}

	return &PrivateKey{
		hash:    privateHash,
		private: key,
		public: &PublicKey{
			hash:   publicHash,
			public: &key.PublicKey,
		},
	}, nil
}

// Encrypt ...
func (key *PrivateKey) Encrypt(plaintext []byte) ([]byte, error) {
	return encrypt(key.hash, plaintext)
}

// Decrypt ...
func (key *PrivateKey) Decrypt(ciphertext []byte) ([]byte, error) {
	return decrypt(key.hash, ciphertext)
}

// Sign ...
func (key *PrivateKey) Sign(data []byte) ([]byte, error) {
	hash := sha256.Sum256(data)

	return rsa.SignPKCS1v15(rand.Reader, key.private, crypto.SHA256, hash[0:])
}

// Verify ...
func (key *PrivateKey) Verify(data []byte, sig []byte) error {
	return key.public.Verify(data, sig)
}

// PublicKey ...
type PublicKey struct {
	hash   []byte
	public *rsa.PublicKey
}

// NewPublicKey ...
func NewPublicKey(file []byte) (*PublicKey, error) {
	key, err := parsePublicKey(file)
	if err != nil {
		return nil, err
	}

	publicHash, err := hash(key)
	if err != nil {
		return nil, err
	}
	return &PublicKey{
		hash:   publicHash,
		public: key,
	}, nil
}

// Verify ...
func (key *PublicKey) Verify(data []byte, sig []byte) error {
	hash := sha256.Sum256(data)

	return rsa.VerifyPKCS1v15(key.public, crypto.SHA256, hash[0:], sig)
}

// parsePrivateKey ...
func parsePrivateKey(privateKey []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privateKey)

	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	i, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return i.(*rsa.PrivateKey), nil
}

// hash ...
func hash(key interface{}) ([]byte, error) {
	data, err := json.Marshal(key)
	if err != nil {
		return nil, err
	}

	hash := sha256.Sum256(data)

	return hash[0:], nil
}

// parsePublicKey ...
func parsePublicKey(publicKey []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKey)

	key, err := x509.ParsePKCS1PublicKey(block.Bytes)
	if err == nil {
		return key, nil
	}

	i, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}

	return i.(*rsa.PublicKey), nil
}

// encrypt ...
func encrypt(key []byte, plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	// Never use more than 2^32 random nonces with a given key because of the risk of a repeat.
	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := aesgcm.Seal(nil, nonce, plaintext, nil)
	return ciphertext, nil
}

// decrypt ...
func decrypt(key, ciphertext []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := aesgcm.NonceSize()
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]

	plaintext, err := aesgcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}
