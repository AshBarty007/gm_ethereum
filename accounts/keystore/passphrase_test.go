// Copyright 2016 The go-ethereum Authors
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

package keystore

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/ethereum/go-ethereum/gmsm"
	"os"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

const (
	veryLightScryptN = 2
	veryLightScryptP = 1
)

// Tests that a json key file can be decrypted and encrypted in multiple rounds.
func TestKeyEncryptDecrypt(t *testing.T) {
	keyjson, err := os.ReadFile("testdata/very-light-scrypt.json")
	if err != nil {
		t.Fatal(err)
	}
	password := ""
	address := common.HexToAddress("45dea0fb0bba44f4fcf290bba71fd57d7117cbb8")

	// Do a few rounds of decryption and encryption
	for i := 0; i < 3; i++ {
		// Try a bad password first
		if _, err := DecryptKey(keyjson, password+"bad"); err == nil {
			t.Errorf("test %d: json key decrypted with bad password", i)
		}
		// Decrypt with the correct password
		key, err := DecryptKey(keyjson, password)
		if err != nil {
			t.Fatalf("test %d: json key failed to decrypt: %v", i, err)
		}
		if key.Address != address {
			t.Errorf("test %d: key address mismatch: have %x, want %x", i, key.Address, address)
		}
		// Recrypt with a new password and start over
		password += "new data appended" // nolint: gosec
		if keyjson, err = EncryptKey(key, password, veryLightScryptN, veryLightScryptP); err != nil {
			t.Errorf("test %d: failed to recrypt key %v", i, err)
		}
	}
}

func TestPassphraseMatch(t *testing.T) {
	auth := "123456"
	k := new(encryptedKeyJSONV3)
	keyjson, err := os.ReadFile("testdata/account1.json")
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(keyjson, k); err != nil {
		t.Fatal(err)
	}
	cryptoJson := k.Crypto

	mac, err := hex.DecodeString(cryptoJson.MAC)
	if err != nil {
		t.Fatal(err)
	}

	cipherText, err := hex.DecodeString(cryptoJson.CipherText)
	if err != nil {
		t.Fatal(err)
	}

	derivedKey, err := getKDFKey(cryptoJson, auth)
	if err != nil {
		t.Fatal(err)
	}

	calculatedMAC := gmsm.SM3(derivedKey[16:32], cipherText)
	t.Log("mac, derivedKey[16:32], cipherText:", hex.EncodeToString(mac), hex.EncodeToString(derivedKey[16:32]), hex.EncodeToString(cipherText))
	t.Log("calculatedMAC:", hex.EncodeToString(calculatedMAC))
	if !bytes.Equal(calculatedMAC, mac) {
		t.Fatal("passphrase 266:calculatedMAC, mac:", hex.EncodeToString(calculatedMAC), hex.EncodeToString(mac))
	} else {
		t.Log("success")
	}
}

func TestUnlockAccount(t *testing.T) {
	_, ks := tmpKeyStore(t, true)
	acc, err := ks.NewAccount("old")
	if err != nil {
		t.Fatalf("failed to create account: %v", acc)
	}
	fmt.Println("========================================================================")

	keyjson, err := ks.Export(acc, "old", "new")
	k := new(encryptedKeyJSONV3)
	if err := json.Unmarshal(keyjson, k); err != nil {
		t.Fatal(err)
	}
	cryptoJson := k.Crypto

	mac, err := hex.DecodeString(cryptoJson.MAC)
	if err != nil {
		t.Fatal(err)
	}

	cipherText, err := hex.DecodeString(cryptoJson.CipherText)
	if err != nil {
		t.Fatal(err)
	}

	auth := "new"
	derivedKey, err := getKDFKey(cryptoJson, auth)
	if err != nil {
		t.Fatal(err)
	}

	calculatedMAC := gmsm.SM3(derivedKey[16:32], cipherText)
	if !bytes.Equal(calculatedMAC, mac) {
		fmt.Println("DecryptDataV3 160:mac, derivedKey[16:32], cipherText:", hex.EncodeToString(mac), hex.EncodeToString(derivedKey[16:32]), hex.EncodeToString(cipherText))
		fmt.Println("calculatedMAC, mac:", hex.EncodeToString(calculatedMAC), hex.EncodeToString(mac))
	} else {
		fmt.Println("success")
	}

}

/*
DecryptDataV3 267:mac, derivedKey[16:32], cipherText: 4c4a46d85a05ed89523a91eb12cf24345d9ff3b782c55a822e5fc377be8e86be 72561824827d4716dc5dc0634fe63fd6 ffc9cee6a4c502b70e9fa16d013c608b539bc4dfecb91cc8df6b948e10b44e9a
DecryptDataV3 268:calculatedMAC: ec296dd65e4311c8dfc38b976d8fff6c03d5962d0af70d00e06d6d3547eb9405

*/
