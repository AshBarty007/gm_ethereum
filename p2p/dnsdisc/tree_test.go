// Copyright 2019 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

package dnsdisc

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"reflect"
	"testing"

	"github.com/davecgh/go-spew/spew"
	"github.com/ethereum/go-ethereum/p2p/enode"
)

func TestParseRoot(t *testing.T) {
	tests := []struct {
		input string
		e     rootEntry
		err   error
	}{
		{
			input: "enrtree-root:v1 e=TO4Q75OQ2N7DX4EOOR7X66A6OM seq=3 sig=N-YY6UB9xD0hFx1Gmnt7v0RfSxch5tKyry2SRDoLx7B4GfPXagwLxQqyf7gAMvApFn_ORwZQekMWa_pXrcGCtw",
			err:   entryError{"root", errSyntax},
		},
		{
			input: "enrtree-root:v1 e=TO4Q75OQ2N7DX4EOOR7X66A6OM l=TO4Q75OQ2N7DX4EOOR7X66A6OM seq=3 sig=N-YY6UB9xD0hFx1Gmnt7v0RfSxch5tKyry2SRDoLx7B4GfPXagwLxQqyf7gAMvApFn_ORwZQekMWa_pXrcGCtw",
			err:   entryError{"root", errInvalidSig},
		},
		{
			input: "enrtree-root:v1 e=QFT4PBCRX4XQCV3VUYJ6BTCEPU l=JGUFMSAGI7KZYB3P7IZW4S5Y3A seq=3 sig=3FmXuVwpa8Y7OstZTx9PIb1mt8FrW7VpDOFv4AaGCsZ2EIHmhraWhe4NxYhQDlw5MjeFXYMbJjsPeKlHzmJREQE",
			e: rootEntry{
				eroot: "QFT4PBCRX4XQCV3VUYJ6BTCEPU",
				lroot: "JGUFMSAGI7KZYB3P7IZW4S5Y3A",
				seq:   3,
				sig:   hexutil.MustDecode("0xdc5997b95c296bc63b3acb594f1f4f21bd66b7c16b5bb5690ce16fe006860ac6761081e686b69685ee0dc588500e5c393237855d831b263b0f78a947ce62511101"),
			},
		},
	}
	for i, test := range tests {
		e, err := parseRoot(test.input)
		if !reflect.DeepEqual(e, test.e) {
			t.Errorf("test %d: wrong entry %s, want %s", i, spew.Sdump(e), spew.Sdump(test.e))
		}
		if err != test.err {
			t.Errorf("test %d: wrong error %q, want %q", i, err, test.err)
		}
	}
}

func TestParseEntry(t *testing.T) {
	testkey := testKey(signingKeySeed)
	//fmt.Println("address: ", gmsm.PubkeyToAddress(testkey.PublicKey))
	//fmt.Println("compress pub", hex.EncodeToString(gmsm.CompressPubkey(&testkey.PublicKey)))
	//fmt.Println("uncompress pub", hex.EncodeToString(gmsm.PubToUnCompressBytes(&testkey.PublicKey)))
	//sig, _ := testkey.Sign(rand.Reader, []byte("hello"), nil)
	//fmt.Println("signature: ", hex.EncodeToString(sig))
	tests := []struct {
		input string
		e     entry
		err   error
	}{
		// Subtrees:
		{
			input: "enrtree-branch:1,2",
			err:   entryError{"branch", errInvalidChild},
		},
		{
			input: "enrtree-branch:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
			err:   entryError{"branch", errInvalidChild},
		},
		{
			input: "enrtree-branch:",
			e:     &branchEntry{},
		},
		{
			input: "enrtree-branch:AAAAAAAAAAAAAAAAAAAA",
			e:     &branchEntry{[]string{"AAAAAAAAAAAAAAAAAAAA"}},
		},
		{
			input: "enrtree-branch:AAAAAAAAAAAAAAAAAAAA,BBBBBBBBBBBBBBBBBBBB",
			e:     &branchEntry{[]string{"AAAAAAAAAAAAAAAAAAAA", "BBBBBBBBBBBBBBBBBBBB"}},
		},
		// Links
		{
			input: "enrtree://AAJFHGCJUUD7LZYIIHWLZNY5VAABT4ZJFFB54MER56ACJETILKYKE@nodes.example.org",
			e:     &linkEntry{"AAJFHGCJUUD7LZYIIHWLZNY5VAABT4ZJFFB54MER56ACJETILKYKE@nodes.example.org", "nodes.example.org", &testkey.PublicKey},
		},
		{
			input: "enrtree://AP62DT7WOTEQZGQZOU474PP3KMEGVTTE7A7NPRXKX3DUD57@nodes.example.org",
			err:   entryError{"link", errBadPubkey},
		},
		{
			input: "enrtree://AP62DT7WONEQZGQZOU474PP3KMEGVTTE7A7NPRXKX3DUD57TQHGIA@nodes.example.org",
			err:   entryError{"link", errBadPubkey},
		},
		// ENRs
		{
			input: "enr:-HW4QAnIkIrwGimW4-j57262Ie6qDB3K1RhzJuIgJ3OPuClsBRjQsKcpDa2WGJ4tsmOyua1XxhRBCxHWfm6D3EImcNWAgmlkgnY0iXNtMnAyNTZ2MaEBFIJd9ZRrvL1LwDU2eGo_ek_iK39T0gTriZPccUwp-9g",
			e:     &enrEntry{node: testNode(nodesSeed1)},
		},
		{
			input: "enr:-HW4QLZHjM4vZXkbp-5xJoHsKSbE7W39FPC8283X-y8oHcHPTnDDlIlzL5ArvDUlHZVDPgmFASrh7cWgLOLxj4wprRkHgmlkgnY0iXNlY3AyNTZrMaEC3t2jLMhDpCDX5mbSEwDn4L3iUfyXzoO8G28XvjGRkrAg=",
			err:   entryError{"enr", errInvalidENR},
		},
		//// Invalid:
		{input: "", err: errUnknownEntry},
		{input: "foo", err: errUnknownEntry},
		{input: "enrtree", err: errUnknownEntry},
		{input: "enrtree-x=", err: errUnknownEntry},
	}
	for i, test := range tests {
		fmt.Println("NO.", i)
		e, err := parseEntry(test.input, enode.ValidSchemes)
		if !reflect.DeepEqual(e, test.e) {
			t.Errorf("!reflect.DeepEqual(e, test.e) test %d: \n wrong entry %s \n want entry  %s", i, spew.Sdump(e), spew.Sdump(test.e))
			/*
				type linkEntry struct {
				    str    string
				    domain string
				    pubkey *sm2.PublicKey
				}
			*/
		}
		if err != test.err {
			t.Errorf("err != test.err test %d: \n wrong error %q \n want error  %q", i, err, test.err)
		}
		fmt.Println("===================================================================================")
	}
}

func TestMakeTree(t *testing.T) {
	nodes := testNodes(nodesSeed2, 50)
	tree, err := MakeTree(2, nodes, nil)
	if err != nil {
		t.Fatal(err)
	}
	txt := tree.ToTXT("")
	if len(txt) < len(nodes)+1 {
		t.Fatal("too few TXT records in output")
	}
}

func TestBase64TXT(t *testing.T) {
	//data := make([]byte, 64)
	//sig := []byte("qweryquwefpsdv,mbvs[aivhjbvzbc,va'hfcn/lzkbv cxvmxvb.vA/JZV")
	//copy(data, sig)
	data, _ := hex.DecodeString("0412539849a507f5e70841ecbcb71da80019f3292943de3091ef802492685ab0a21def2dcd6cf18495d0cc7b854a4f8d58f0850238ea3d35cf8a611f80f751316c")
	str := b64format.EncodeToString(data)
	sigb, err := b64format.DecodeString(str)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(data, sigb) {
		t.Error("base64 decode failed")
	}
	//t.Log("end", len(data), len(sig), len(sigb))
	//
	//compress pub 0012539849a507f5e70841ecbcb71da80019f3292943de3091ef802492685ab0a2 ABJTmEmlB_XnCEHsvLcdqAAZ8ykpQ94wke-AJJJoWrCi
	//uncompress pub 0412539849a507f5e70841ecbcb71da80019f3292943de3091ef802492685ab0a21def2dcd6cf18495d0cc7b854a4f8d58f0850238ea3d35cf8a611f80f751316c BBJTmEmlB_XnCEHsvLcdqAAZ8ykpQ94wke-AJJJoWrCiHe8tzWzxhJXQzHuFSk-NWPCFAjjqPTXPimEfgPdRMWw
	//sign "hello" 0fff90b16bb7c2e083db981ceb6770f6688ab9e8add5555cd0cb5e46ba8c04d6ea70db6ab3e680a5a27f4a27cf4e30a5edcf207e4f2ec27e3e3ecf1a9f75c871
	t.Log(str)
}

func TestBase32TXT(t *testing.T) {
	data := "AKPYQIUQIL7PSIACI32J7FGZW56E5FKHEFCCOFHILBIMW3M6LWXS2"
	sigb, err := b32format.DecodeString(data)
	if err != nil {
		t.Fatal(err)
	}
	str := b32format.EncodeToString(sigb)
	if str != data {
		t.Error("base64 decode failed")
	}
	t.Log(str)

	pub := common.Hex2Bytes("0012539849a507f5e70841ecbcb71da80019f3292943de3091ef802492685ab0a2")
	str = b32format.EncodeToString(pub)
	t.Log(str)
}
