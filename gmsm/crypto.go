package gmsm

import (
	"bufio"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/gmsm/sm2"
	"github.com/ethereum/go-ethereum/gmsm/sm3"
	"github.com/ethereum/go-ethereum/rlp"
	"hash"
	"io"
	"math/big"
	"os"
)

// SignatureLength indicates the byte length required to carry a signature with recovery id.
const SignatureLength = 64

// RecoveryIDOffset points to the byte offset within the signature that contains the recovery id.
const RecoveryIDOffset = 64

// DigestLength sets the signature digest exact length
const DigestLength = 32

const PublicKeyLength = 33

var (
	sm2p256v1N, _  = new(big.Int).SetString("FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123", 16)
	sm2p256v1halfN = new(big.Int).Div(sm2p256v1N, big.NewInt(2))
)

var errInvalidPubkey = errors.New("invalid sm2p256v1 public key")

type Sm3State interface {
	hash.Hash
	//Read([]byte) (int, error)
}

func NewSm3State() Sm3State {
	return sm3.New().(Sm3State)
}

// HashData hashes the provided data using the KeccakState and returns a 32 byte hash
func HashData(kh Sm3State, data []byte) (h common.Hash) {
	kh.Reset()
	kh.Write(data)
	//kh.Read(h[:])

	h.SetBytes(kh.Sum(nil))
	return h
}

func SM3(data ...[]byte) []byte {
	b := make([]byte, 32)
	d := NewSm3State()
	for _, b := range data {
		d.Write(b)
	}
	//d.Read(b)

	b = d.Sum(nil)
	return b
}

func SM3Hash(data ...[]byte) (h common.Hash) {
	d := NewSm3State()
	for _, b := range data {
		d.Write(b)
	}
	//d.Read(h[:])

	h.SetBytes(d.Sum(nil))
	return h
}

// SM3Size512 该方法未实现,sm3没有512位的哈希
func SM3Size512(data ...[]byte) []byte {
	b := make([]byte, 64)
	d := NewSm3State()
	for _, b := range data {
		d.Write(b)
	}
	//d.Read(b)

	b = d.Sum(nil)
	b = append(b, b...)
	return b
}

// CreateAddress creates an ethereum address given the bytes and the nonce
func CreateAddress(b common.Address, nonce uint64) common.Address {
	data, _ := rlp.EncodeToBytes([]interface{}{b, nonce})
	return common.BytesToAddress(SM3(data)[12:])
}

// CreateAddress2 creates an ethereum address given the address bytes, initial
// contract code hash and a salt.
func CreateAddress2(b common.Address, salt [32]byte, inithash []byte) common.Address {
	return common.BytesToAddress(SM3([]byte{0xff}, b.Bytes(), salt[:], inithash)[12:])
}

func ToSM2(d []byte) (*sm2.PrivateKey, error) {
	return toSM2(d, true)
}

func ToSM2Unsafe(d []byte) *sm2.PrivateKey {
	priv, _ := toSM2(d, false)
	return priv
}

func toSM2(d []byte, strict bool) (*sm2.PrivateKey, error) {
	priv := new(sm2.PrivateKey)
	priv.PublicKey.Curve = P256Sm2()
	if strict && 8*len(d) != priv.Params().BitSize {
		return nil, fmt.Errorf("invalid length, need %d bits", priv.Params().BitSize)
	}
	priv.D = new(big.Int).SetBytes(d)

	// The priv.D must < N
	if priv.D.Cmp(sm2p256v1N) >= 0 {
		return nil, fmt.Errorf("invalid private key, >=N")
	}
	// The priv.D must not be zero or negative.
	if priv.D.Sign() <= 0 {
		return nil, fmt.Errorf("invalid private key, zero or negative")
	}

	priv.PublicKey.X, priv.PublicKey.Y = priv.PublicKey.Curve.ScalarBaseMult(d)
	if priv.PublicKey.X == nil {
		return nil, errors.New("invalid private key")
	}
	return priv, nil
}

func FromSM2(priv *sm2.PrivateKey) []byte {
	if priv == nil {
		return nil
	}
	return math.PaddedBigBytes(priv.D, priv.Params().BitSize/8)
}

func UnmarshalPubkey(pub []byte) (*sm2.PublicKey, error) {
	x, y := elliptic.Unmarshal(P256Sm2(), pub)
	if x == nil {
		return nil, errInvalidPubkey
	}
	return &sm2.PublicKey{Curve: P256Sm2(), X: x, Y: y}, nil
}

func FromSM2Pub(pub *sm2.PublicKey) []byte {
	if pub == nil || pub.X == nil || pub.Y == nil {
		return nil
	}
	return elliptic.Marshal(P256Sm2(), pub.X, pub.Y)
}

func HexToSM2(hexkey string) (*sm2.PrivateKey, error) {
	b, err := hex.DecodeString(hexkey)
	if byteErr, ok := err.(hex.InvalidByteError); ok {
		return nil, fmt.Errorf("invalid hex character %q in private key", byte(byteErr))
	} else if err != nil {
		return nil, errors.New("invalid hex data for private key")
	}
	return ToSM2(b)
}

func LoadSM2(file string) (*sm2.PrivateKey, error) {
	fd, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer fd.Close()

	r := bufio.NewReader(fd)
	buf := make([]byte, 64)
	n, err := readASCII(buf, r)
	if err != nil {
		return nil, err
	} else if n != len(buf) {
		return nil, fmt.Errorf("key file too short, want 64 hex characters")
	}
	if err := checkKeyFileEnd(r); err != nil {
		return nil, err
	}

	return HexToSM2(string(buf))
}

func readASCII(buf []byte, r *bufio.Reader) (n int, err error) {
	for ; n < len(buf); n++ {
		buf[n], err = r.ReadByte()
		switch {
		case err == io.EOF || buf[n] < '!':
			return n, nil
		case err != nil:
			return n, err
		}
	}
	return n, nil
}

// checkKeyFileEnd skips over additional newlines at the end of a key file.
func checkKeyFileEnd(r *bufio.Reader) error {
	for i := 0; ; i++ {
		b, err := r.ReadByte()
		switch {
		case err == io.EOF:
			return nil
		case err != nil:
			return err
		case b != '\n' && b != '\r':
			return fmt.Errorf("invalid character %q at end of key file", b)
		case i >= 2:
			return errors.New("key file too long, want 64 hex characters")
		}
	}
}

func SaveSM2(file string, key *sm2.PrivateKey) error {
	k := hex.EncodeToString(FromSM2(key))
	return os.WriteFile(file, []byte(k), 0600)
}

func GenerateKey() (*sm2.PrivateKey, error) {
	return sm2.GenerateKey(rand.Reader)
}

// ValidateSignatureValues 注意SM2算法没有v值
func ValidateSignatureValues(r, s *big.Int, homestead bool) bool {
	if r.Cmp(common.Big1) < 0 || s.Cmp(common.Big1) < 0 {
		return false
	}
	// reject upper range of s values (ECDSA malleability)
	// see discussion in secp256k1/libsecp256k1/include/secp256k1.h
	if homestead && s.Cmp(sm2p256v1halfN) > 0 {
		return false
	}
	// Frontier: allow s to be in full N range
	return r.Cmp(sm2p256v1N) < 0 && s.Cmp(sm2p256v1N) < 0
}

func PubkeyToAddress(p sm2.PublicKey) common.Address {
	pubBytes := FromSM2Pub(&p)
	return common.BytesToAddress(SM3(pubBytes[1:])[12:])
}

func zeroBytes(bytes []byte) {
	for i := range bytes {
		bytes[i] = 0
	}
}

func P256Sm2() elliptic.Curve {
	return sm2.P256Sm2()
}

func Sign(digestHash []byte, prv *sm2.PrivateKey) (sig []byte, err error) {
	if len(digestHash) != DigestLength {
		return nil, fmt.Errorf("hash is required to be exactly %d bytes (%d)", DigestLength, len(digestHash))
	}
	return prv.Sign(rand.Reader, digestHash, nil)
}

func VerifySignature(pubkey, digestHash, signature []byte) bool {
	var publicKey *sm2.PublicKey
	if len(pubkey) == PublicKeyLength {
		publicKey = DecompressPubkey(pubkey)
	} else if len(pubkey) == 65 {
		publicKey = UnCompressBytesToPub(pubkey)
	} else if len(pubkey) == 64 {
		publicKey = UnCompressBytesToPub2(pubkey)
	} else {
		return false
	}

	return publicKey.Verify(digestHash, signature)
}

func DecompressPubkey(pubkey []byte) *sm2.PublicKey {
	if len(pubkey) != PublicKeyLength {
		return nil
	}
	return sm2.Decompress(pubkey)
}

func CompressPubkey(pubkey *sm2.PublicKey) []byte {
	return sm2.Compress(pubkey)
}
