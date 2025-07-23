package gmsm

import (
	"github.com/ethereum/go-ethereum/gmsm/sm2"
	"math/big"
)

const (
	BitSize    = 256
	KeyBytes   = (BitSize + 7) / 8
	UnCompress = 0x04
)

func GetUnCompressBytes(pub *sm2.PublicKey) []byte {
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

func bigIntTo32Bytes(bn *big.Int) []byte {
	byteArr := bn.Bytes()
	byteArrLen := len(byteArr)
	if byteArrLen == KeyBytes {
		return byteArr
	}
	byteArr = append(make([]byte, KeyBytes-byteArrLen), byteArr...)
	return byteArr
}
