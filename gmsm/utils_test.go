package gmsm

import (
	"bytes"
	"crypto/rand"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/gmsm/sm2"
	"github.com/ethereum/go-ethereum/gmsm/x509"
	"golang.org/x/crypto/cryptobyte"
	cbasn1 "golang.org/x/crypto/cryptobyte/asn1"
	"math/big"
	"net"
	"os"
	"testing"
	"time"
)

var (
	msg                = []byte("hello world")
	password           = []byte("1234")
	privateKeyFilaName = "sm2.pem"
	publicKeyFilaName  = "sm2pub.pem"
)

func TestGeneratePem(t *testing.T) {
	priv, err := sm2.GenerateKey(nil) // 生成密钥对
	if err != nil {
		t.Fatal(err)
	}
	privPem, err := x509.WritePrivateKeyToPem(priv, password) // 生成密钥文件
	if err != nil {
		t.Fatal(err)
	}
	pubKey, _ := priv.Public().(*sm2.PublicKey)
	pubkeyPem, err := x509.WritePublicKeyToPem(pubKey) // 生成公钥文件

	toPem(pubkeyPem, privateKeyFilaName, true)
	toPem(privPem, publicKeyFilaName, false)
}

func TestReadPrivateKey(t *testing.T) {
	key := fromPem(privateKeyFilaName)
	privateKey, err := x509.ReadPrivateKeyFromPem(key.Bytes, password)
	if err != nil {
		t.Fatal(err)
		return
	}
	sig, _ := privateKey.Sign(rand.Reader, msg, nil)
	t.Log(string(sig))

	//pub := fromPem(publicKeyFilaName)
	//publicKey, err := x509.ReadPublicKeyFromPem(pub.Bytes)
	//if err != nil {
	//	t.Fatal(err)
	//	return
	//}
	//result := publicKey.Verify(msg, sig)
	//log.Printf("result: %v\n", result)
}

func toPem(b []byte, name string, p bool) {
	// 创建PEM块
	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: b,
	}

	if p {
		pemBlock.Type = "PUBLIC KEY"
	}

	// 创建或打开文件
	f, err := os.Create(name)
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer f.Close()

	// 写入PEM格式数据到文件
	if err := pem.Encode(f, pemBlock); err != nil {
		fmt.Println("Error encoding PEM block:", err)
		return
	}

	fmt.Println("successfully written")
}

func fromPem(name string) *pem.Block {
	f, err := os.ReadFile(name)
	if err != nil {
		fmt.Println("Error opening file:", err)
		return nil
	}

	// 写入PEM格式数据到文件
	p, _ := pem.Decode(f)

	return p
}

func TestPriToPem(t *testing.T) {
	// 生成SM2密钥对
	privateKey, err := HexToSM2("3e8ad6b30699f7058e5976df05da28f0855395b77b87b402ec2661c0092d6374") //sm2.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating SM2 key pair:", err)
		return
	}
	marshalSm2PriKey, err := x509.WritePrivateKeyToPem(privateKey, nil)
	if err != nil {
		return
	}

	pemBlock := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: marshalSm2PriKey,
	}

	// 创建或打开文件
	f, err := os.Create("sm2.pem")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer f.Close()

	// 写入PEM格式数据到文件
	if err := pem.Encode(f, pemBlock); err != nil {
		fmt.Println("Error encoding PEM block:", err)
		return
	}

	fs, err := os.ReadFile("sm2.pem")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}

	// 写入PEM格式数据到文件
	block, _ := pem.Decode(fs)

	_, err = x509.ReadPrivateKeyFromPem(marshalSm2PriKey, nil)
	if err != nil {
		t.Fatal(err)
		return
	}

	_, err = x509.ReadPrivateKeyFromPem(block.Bytes, nil)
	if err != nil {
		t.Fatal(err)
		return
	}
}

func TestPubToPem(t *testing.T) {
	// 生成SM2密钥对
	privateKey, err := HexToSM2("3e8ad6b30699f7058e5976df05da28f0855395b77b87b402ec2661c0092d6374") //sm2.GenerateKey(rand.Reader)
	if err != nil {
		fmt.Println("Error generating SM2 key pair:", err)
		return
	}

	publicKey := privateKey.Public().(*sm2.PublicKey)

	marshalSm2PriKey, err := x509.WritePublicKeyToPem(publicKey)
	if err != nil {
		return
	}

	pemBlock := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: marshalSm2PriKey,
	}

	// 创建或打开文件
	f, err := os.Create("sm2pub.pem")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer f.Close()

	// 写入PEM格式数据到文件
	if err := pem.Encode(f, pemBlock); err != nil {
		fmt.Println("Error encoding PEM block:", err)
		return
	}

	fs, err := os.ReadFile("sm2pub.pem")
	if err != nil {
		fmt.Println("Error opening file:", err)
		return
	}

	// 写入PEM格式数据到文件
	block, _ := pem.Decode(fs)

	_, err = x509.ReadPublicKeyFromPem(marshalSm2PriKey)
	if err != nil {
		t.Fatal(err)
		return
	}

	_, err = x509.ReadPublicKeyFromPem(block.Bytes)
	if err != nil {
		t.Fatal(err)
		return
	}
}

func TestCreateCert(t *testing.T) {

	template := x509.Certificate{
		// SerialNumber is negative to ensure that negative
		// values are parsed. This is due to the prevalence of
		// buggy code that produces certificates with negative
		// serial numbers.
		SerialNumber: big.NewInt(-1),
		Subject: pkix.Name{
			CommonName:   "test.example.com",
			Organization: []string{"TEST"},
			Country:      []string{"China"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{
					Type:  []int{2, 5, 4, 42},
					Value: "Gopher",
				},
				// This should override the Country, above.
				{
					Type:  []int{2, 5, 4, 6},
					Value: "NL",
				},
			},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Date(2021, time.October, 10, 12, 1, 1, 1, time.UTC),

		//		SignatureAlgorithm: ECDSAWithSHA256,
		SignatureAlgorithm: x509.SM2WithSM3,

		SubjectKeyId: []byte{1, 2, 3, 4},
		KeyUsage:     x509.KeyUsageCertSign,

		//ExtKeyUsage:        []ExtKeyUsage{ExtKeyUsageClientAuth, ExtKeyUsageServerAuth},
		//UnknownExtKeyUsage: testUnknownExtKeyUsage,

		BasicConstraintsValid: true,
		IsCA:                  true,

		OCSPServer:            []string{"http://ocsp.example.com"},
		IssuingCertificateURL: []string{"http://crt.example.com/ca1.crt"},

		DNSNames:       []string{"test.example.com"},
		EmailAddresses: []string{"gopher@golang.org"},
		IPAddresses:    []net.IP{net.IPv4(127, 0, 0, 1).To4(), net.ParseIP("2001:4860:0:2001::68")},

		PolicyIdentifiers:   []asn1.ObjectIdentifier{[]int{1, 2, 3}},
		PermittedDNSDomains: []string{".example.com", "example.com"},

		CRLDistributionPoints: []string{"http://crl1.example.com/ca1.crl", "http://crl2.example.com/ca1.crl"},

		ExtraExtensions: []pkix.Extension{
			{
				Id:    []int{1, 2, 3, 4},
				Value: []byte("extra extension"),
			},
			// This extension should override the SubjectKeyId, above.
			{
				Id:       []int{2, 5, 29, 14},
				Critical: false,
				Value:    []byte{0x04, 0x04, 4, 3, 2, 1},
			},
		},
	}
	privKey, _ := HexToSM2("3e8ad6b30699f7058e5976df05da28f0855395b77b87b402ec2661c0092d6374") //sm2.GenerateKey(rand.Reader)
	pubKey := privKey.Public().(*sm2.PublicKey)
	certBytes, err := x509.CreateCertificateToPem(&template, &template, pubKey, privKey)
	if err != nil {
		t.Fatal("failed to create cert file")
	}
	pemBlock := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}

	f, err := os.Create("sm2cert.pem")
	if err != nil {
		fmt.Println("Error creating file:", err)
		return
	}
	defer f.Close()

	if err := pem.Encode(f, pemBlock); err != nil {
		fmt.Println("Error encoding PEM block:", err)
		return
	}
}

func TestDecodeSignature(t *testing.T) {
	priv, _ := HexToSM2("289c2857d4598e37fb9647507e47a309d6133539bf21a8b9cb6df88fd5232032")
	r, s, err := sm2.Sm2Sign(priv, msg, nil, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var b cryptobyte.Builder
	b.AddASN1(cbasn1.SEQUENCE, func(b *cryptobyte.Builder) {
		b.AddASN1BigInt(r)
		b.AddASN1BigInt(s)
	})
	sig, _ := b.Bytes()
	t.Logf("signature: %v", sig)
	t.Logf("signature: %v", len(sig))

	var (
		rz, sz = &big.Int{}, &big.Int{}
		inner  cryptobyte.String
	)
	input := cryptobyte.String(sig)
	if !input.ReadASN1(&inner, cbasn1.SEQUENCE) ||
		!input.Empty() ||
		!inner.ReadASN1Integer(rz) ||
		!inner.ReadASN1Integer(sz) ||
		!inner.Empty() {
		t.Log("invalid signature")
	}
	t.Logf("encode x,y: %v %v", r, s)
	t.Logf("decode x,y: %v %v", rz, sz)

}

func TestCase(t *testing.T) {
	priv, _ := HexToSM2("AE189473BBCA1E6605475F0C49F732401D194620EAD7AEC028CF2098BB953F52")

	hash := SM3(msg)
	sign, err := Sign(hash, priv)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("sign: %d", len(sign))

	hx, _ := priv.Sign(rand.Reader, msg, nil)
	t.Logf("hx: %d", len(hx))

	addr := PubkeyToAddress(priv.PublicKey)
	t.Logf("addr: %v", addr)
}

func TestSignRS(t *testing.T) {
	key, _ := HexToSM2(testPrivHex)

	data := SM3([]byte("foo"))
	sig, err := Sign(data, key)
	if err != nil {
		t.Errorf("Sign error: %s", err)
	}

	r, s, _ := sm2.Sm2Sign(key, msg, nil, rand.Reader)

	fmt.Printf("signature length: %d\n", len(sig))

	r1 := new(big.Int).SetBytes(sig[:32])
	s1 := new(big.Int).SetBytes(sig[32:64])

	if r.Cmp(r1) == 0 {
		t.Errorf("r is equal to sign r")
	}

	if s.Cmp(s1) == 0 {
		t.Errorf("s is equal to sign s")
	}
}

func TestDecompressPubkey(t *testing.T) {
	key, _ := GenerateKey()
	pub := PubToUnCompressBytes2(&key.PublicKey)
	fmt.Println("len(pub): ", len(pub))
	newKey := UnCompressBytesToPub2(pub)

	data := []byte("message")
	b, _ := newKey.EncryptAsn1(data, rand.Reader)
	res, _ := key.DecryptAsn1(b)

	if bytes.Equal(res, data) {
		fmt.Println("success")
	} else {
		fmt.Println("fail")
	}
}

func TestCopyBytes(t *testing.T) {
	data := []byte("message")
	dataLen := len(data)
	fmt.Println("len(data): ", len(data), string(data))
	l := make([]byte, dataLen*4)
	copy(l, data)
	copy(l[dataLen:], data)
	copy(l[dataLen*2:], data)
	copy(l[dataLen*3:], data)
	fmt.Println("l: ", len(l), string(l))
}

func TestKKK(t *testing.T) {
	priv, _ := ToSM2(common.Hex2Bytes("39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d")) //GenerateKey()
	data := FromSM2(priv)
	fmt.Println(hex.EncodeToString(data), PubkeyToAddress(priv.PublicKey))

	pub := CompressPubkey(&priv.PublicKey)
	desPub := DecompressPubkey(pub)
	signer := PubkeyToAddress(*desPub)
	fmt.Println(hex.EncodeToString(pub), signer)
}
