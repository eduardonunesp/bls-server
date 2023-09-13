package bls

import (
	"crypto/rand"

	chiaBLS "github.com/chuwt/chia-bls-go"
)

const bitSize = 256

func NewKeyPair() *KeyPair {
	entropy := make([]byte, bitSize/8)
	_, _ = rand.Read(entropy) // err is always nil
	return &KeyPair{
		secretKey: chiaBLS.KeyFromBytes(entropy),
	}
}

func NewKeyPairFromMnemonic(mnemonic string, passphrase string) *KeyPair {
	return &KeyPair{
		secretKey: chiaBLS.KeyGenWithMnemonic(mnemonic, passphrase),
	}
}

func (kp *KeyPair) GetPublicKey() []byte {
	return kp.secretKey.GetPublicKey().Bytes()
}

func (kp *KeyPair) GetHexPublicKey() string {
	return kp.secretKey.GetPublicKey().Hex()
}
