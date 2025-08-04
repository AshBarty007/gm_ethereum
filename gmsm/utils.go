package gmsm

import (
	"crypto/elliptic"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/gmsm/sm2"
	"math/big"
)

const (
	BitSize    = 256
	KeyBytes   = (BitSize + 7) / 8
	UnCompress = 0x04
)

func UnCompressBytesToPub(e []byte) *sm2.PublicKey {
	key := &sm2.PublicKey{}
	key.X = new(big.Int).SetBytes(e[1:33])
	key.Y = new(big.Int).SetBytes(e[33:])
	key.Curve = sm2.P256Sm2()
	return key
}

func UnCompressBytesToPub2(e []byte) *sm2.PublicKey {
	p := &sm2.PublicKey{Curve: sm2.P256Sm2(), X: new(big.Int), Y: new(big.Int)}
	half := len(e) / 2
	p.X.SetBytes(e[:half])
	p.Y.SetBytes(e[half:])
	if !p.Curve.IsOnCurve(p.X, p.Y) {
		return nil
	}
	return p
}

func PubToUnCompressBytes(pub *sm2.PublicKey) []byte {
	xBytes := bigIntTo32Bytes(pub.X)
	yBytes := bigIntTo32Bytes(pub.Y)
	xl := len(xBytes)
	yl := len(yBytes)

	raw := make([]byte, 1+KeyBytes*2)
	raw[0] = UnCompress
	if xl > KeyBytes {
		copy(raw[1:1+KeyBytes], xBytes[xl-KeyBytes:])
	} else if xl < KeyBytes {
		copy(raw[1+(KeyBytes-xl):1+KeyBytes], xBytes)
	} else {
		copy(raw[1:1+KeyBytes], xBytes)
	}

	if yl > KeyBytes {
		copy(raw[1+KeyBytes:], yBytes[yl-KeyBytes:])
	} else if yl < KeyBytes {
		copy(raw[1+KeyBytes+(KeyBytes-yl):], yBytes)
	} else {
		copy(raw[1+KeyBytes:], yBytes)
	}
	return raw
}

func PubToUnCompressBytes2(key *sm2.PublicKey) []byte {
	var e [64]byte
	math.ReadBits(key.X, e[:32])
	math.ReadBits(key.Y, e[32:])
	return e[:]
}

func bigIntTo32Bytes(bn *big.Int) []byte {
	byteArr := bn.Bytes()
	byteArrLen := len(byteArr)
	if byteArrLen == KeyBytes {
		return byteArr
	}
	byteArr = append(make([]byte, KeyBytes-byteArrLen), byteArr...)
	return byteArr
}

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

func SigToPub(hash, sig []byte) (*sm2.PublicKey, error) {
	s, err := Ecrecover(hash, sig)
	if err != nil {
		return nil, err
	}

	x, y := elliptic.Unmarshal(P256Sm2(), s)
	return &sm2.PublicKey{Curve: P256Sm2(), X: x, Y: y}, nil
}
