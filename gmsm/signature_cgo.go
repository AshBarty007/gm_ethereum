//go:build !nacl && !js && cgo && !gofuzz
// +build !nacl,!js,cgo,!gofuzz

package gmsm

import "C"
import (
	"crypto/elliptic"
	"errors"
	"github.com/ethereum/go-ethereum/gmsm/sm2"
)

// Ecrecover 国密算法不支持恢复公钥，该方法弃用
func Ecrecover(hash, sig []byte) ([]byte, error) {
	//if len(hash) != 32 {
	//	return nil, errors.New("invalid message length, need 32 bytes")
	//}
	//if err := checkSignature(sig); err != nil {
	//	return nil, err
	//}

	var publicKey = make([]byte, 65)
	return publicKey, nil
}

func checkSignature(sig []byte) error {
	if len(sig) != 65 {
		return errors.New("invalid signature length")
	}
	if sig[64] >= 4 {
		return errors.New("invalid signature recovery id")
	}
	return nil
}

// SigToPub returns the public key that created the given signature.
func SigToPub(hash, sig []byte) (*sm2.PublicKey, error) {
	s, err := Ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(P256Sm2(), s)
	return &sm2.PublicKey{Curve: P256Sm2(), X: x, Y: y}, nil
}

func VerifySignature(pubkey, digestHash, signature []byte) bool {
	publicKey := DecompressPubkey(pubkey) //pubkey是不是压缩公钥
	return publicKey.Verify(digestHash, signature)
}

func DecompressPubkey(pubkey []byte) *sm2.PublicKey {
	return sm2.Decompress(pubkey)
}

func CompressPubkey(pubkey *sm2.PublicKey) []byte {
	return sm2.Compress(pubkey)
}
