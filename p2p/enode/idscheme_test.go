// Copyright 2018 The go-ethereum Authors
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

package enode

import (
	"bytes"
	"encoding/hex"
	"github.com/ethereum/go-ethereum/gmsm"
	"github.com/ethereum/go-ethereum/gmsm/sm2"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/p2p/enr"
	"github.com/ethereum/go-ethereum/rlp"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var (
	privkey, _ = gmsm.HexToSM2("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")
	pubkey     = &privkey.PublicKey
)

func TestEmptyNodeID(t *testing.T) {
	var r enr.Record
	if addr := ValidSchemes.NodeAddr(&r); addr != nil {
		t.Errorf("wrong address on empty record: got %v, want %v", addr, nil)
	}

	require.NoError(t, SignV4(&r, privkey))
	expected := "a448f24c6d18e575453db13171562b71999873db5b286df957af199ec94617f7"
	assert.Equal(t, expected, hex.EncodeToString(ValidSchemes.NodeAddr(&r)))
}

// Checks that failure to sign leaves the record unmodified.
func TestSignError(t *testing.T) {
	invalidKey := &sm2.PrivateKey{D: new(big.Int), PublicKey: *pubkey}

	var r enr.Record
	emptyEnc, _ := rlp.EncodeToBytes(&r)
	if err := SignV4(&r, invalidKey); err == nil {
		t.Fatal("expected error from SignV4")
	}
	newEnc, _ := rlp.EncodeToBytes(&r)
	if !bytes.Equal(newEnc, emptyEnc) {
		t.Fatal("record modified even though signing failed")
	}
}

// TestGetSetSecp256k1 tests encoding/decoding and setting/getting of the Secp256k1 key.
func TestGetSetSecp256k1(t *testing.T) {
	var r enr.Record
	if err := SignV4(&r, privkey); err != nil {
		t.Fatal(err)
	}

	var pk Sm2p256v1
	require.NoError(t, r.Load(&pk))
	assert.EqualValues(t, pubkey, &pk)
}

func TestSign(t *testing.T) {
	v := Sm2p256v1(privkey.PublicKey)
	t.Log(v.ENRKey())
}

// invalid sig
// 65
// 65f97bdb655c814a8f9755d748d599e2e6d6cf0fa352c93f617ab1e83cbc348924ce75628aea62679c63f1077e6326620ee32ae814dc3746e3925990d31def6100
// Zfl722VcgUqPl1XXSNWZ4ubWzw-jUsk_YXqx6Dy8NIkkznViiupiZ5xj8Qd-YyZiDuMq6BTcN0bjklmQ0x3vYQA
