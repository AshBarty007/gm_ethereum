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

package backends

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/ethereum/go-ethereum/common/math"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/state/snapshot"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/gmsm"
	"github.com/ethereum/go-ethereum/gmsm/sm3"
	"github.com/ethereum/go-ethereum/trie"
	"math/big"
	"math/rand"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

func TestSimulatedBackend(t *testing.T) {
	var gasLimit uint64 = 8000029
	key, _ := gmsm.HexToSM2("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291") //gmsm.GenerateKey() // nolint: gosec
	auth, _ := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))
	genAlloc := make(core.GenesisAlloc)
	genAlloc[auth.From] = core.GenesisAccount{Balance: big.NewInt(9223372036854775807)}

	sim := NewSimulatedBackend(genAlloc, gasLimit)
	defer sim.Close()

	// should return an error if the tx is not found
	txHash := common.HexToHash("2")
	_, isPending, err := sim.TransactionByHash(context.Background(), txHash)

	if isPending {
		t.Fatal("transaction should not be pending")
	}
	if err != ethereum.NotFound {
		t.Fatalf("err should be `ethereum.NotFound` but received %v", err)
	}

	// generate a transaction and confirm you can retrieve it
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	code := `6060604052600a8060106000396000f360606040526008565b00`
	var gas uint64 = 3000000
	tx := types.NewContractCreation(0, big.NewInt(0), gas, gasPrice, common.FromHex(code))
	tx, _ = types.SignTx(tx, types.HomesteadSigner{}, key)

	err = sim.SendTransaction(context.Background(), tx)
	if err != nil {
		t.Fatal("error sending transaction", err)
	}

	txHash = tx.Hash()
	_, isPending, err = sim.TransactionByHash(context.Background(), txHash)
	if err != nil {
		t.Fatalf("error getting transaction with hash: %v", txHash.String())
	}
	if !isPending {
		t.Fatal("transaction should have pending status")
	}

	sim.Commit()
	_, isPending, err = sim.TransactionByHash(context.Background(), txHash)
	if err != nil {
		t.Fatalf("error getting transaction with hash: %v", txHash.String())
	}
	if isPending {
		t.Fatal("transaction should not have pending status")
	}
}

var testKey, _ = gmsm.HexToSM2("b71c71a67e1177ad4e901695e1b4b9ee17ae16c6668d313eac2f96dbcda3f291")

//	 the following is based on this contract:
//	 contract T {
//	 	event received(address sender, uint amount, bytes memo);
//	 	event receivedAddr(address sender);
//
//	 	function receive(bytes calldata memo) external payable returns (string memory res) {
//	 		emit received(msg.sender, msg.value, memo);
//	 		emit receivedAddr(msg.sender);
//			    return "hello world";
//	 	}
//	 }
const abiJSON = `[ { "constant": false, "inputs": [ { "name": "memo", "type": "bytes" } ], "name": "receive", "outputs": [ { "name": "res", "type": "string" } ], "payable": true, "stateMutability": "payable", "type": "function" }, { "anonymous": false, "inputs": [ { "indexed": false, "name": "sender", "type": "address" }, { "indexed": false, "name": "amount", "type": "uint256" }, { "indexed": false, "name": "memo", "type": "bytes" } ], "name": "received", "type": "event" }, { "anonymous": false, "inputs": [ { "indexed": false, "name": "sender", "type": "address" } ], "name": "receivedAddr", "type": "event" } ]`
const abiBin = `0x608060405234801561001057600080fd5b506102a0806100206000396000f3fe60806040526004361061003b576000357c010000000000000000000000000000000000000000000000000000000090048063a69b6ed014610040575b600080fd5b6100b76004803603602081101561005657600080fd5b810190808035906020019064010000000081111561007357600080fd5b82018360208201111561008557600080fd5b803590602001918460018302840111640100000000831117156100a757600080fd5b9091929391929390505050610132565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156100f75780820151818401526020810190506100dc565b50505050905090810190601f1680156101245780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60607f75fd880d39c1daf53b6547ab6cb59451fc6452d27caa90e5b6649dd8293b9eed33348585604051808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001848152602001806020018281038252848482818152602001925080828437600081840152601f19601f8201169050808301925050509550505050505060405180910390a17f46923992397eac56cf13058aced2a1871933622717e27b24eabc13bf9dd329c833604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390a16040805190810160405280600b81526020017f68656c6c6f20776f726c6400000000000000000000000000000000000000000081525090509291505056fea165627a7a72305820ff0c57dad254cfeda48c9cfb47f1353a558bccb4d1bc31da1dae69315772d29e0029`
const deployedCode = `60806040526004361061003b576000357c010000000000000000000000000000000000000000000000000000000090048063a69b6ed014610040575b600080fd5b6100b76004803603602081101561005657600080fd5b810190808035906020019064010000000081111561007357600080fd5b82018360208201111561008557600080fd5b803590602001918460018302840111640100000000831117156100a757600080fd5b9091929391929390505050610132565b6040518080602001828103825283818151815260200191508051906020019080838360005b838110156100f75780820151818401526020810190506100dc565b50505050905090810190601f1680156101245780820380516001836020036101000a031916815260200191505b509250505060405180910390f35b60607f75fd880d39c1daf53b6547ab6cb59451fc6452d27caa90e5b6649dd8293b9eed33348585604051808573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001848152602001806020018281038252848482818152602001925080828437600081840152601f19601f8201169050808301925050509550505050505060405180910390a17f46923992397eac56cf13058aced2a1871933622717e27b24eabc13bf9dd329c833604051808273ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200191505060405180910390a16040805190810160405280600b81526020017f68656c6c6f20776f726c6400000000000000000000000000000000000000000081525090509291505056fea165627a7a72305820ff0c57dad254cfeda48c9cfb47f1353a558bccb4d1bc31da1dae69315772d29e0029`

// expected return value contains "hello world"
var expectedReturn = []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 32, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 11, 104, 101, 108, 108, 111, 32, 119, 111, 114, 108, 100, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

func simTestBackend(testAddr common.Address) *SimulatedBackend {
	return NewSimulatedBackend(
		core.GenesisAlloc{
			testAddr: {Balance: big.NewInt(10000000000000000)},
		}, 10000000,
	)
}

func TestNewSimulatedBackend(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	expectedBal := big.NewInt(10000000000000000)
	sim := simTestBackend(testAddr)
	defer sim.Close()

	if sim.config != params.AllEthashProtocolChanges {
		t.Errorf("expected sim config to equal params.AllEthashProtocolChanges, got %v", sim.config)
	}

	if sim.blockchain.Config() != params.AllEthashProtocolChanges {
		t.Errorf("expected sim blockchain config to equal params.AllEthashProtocolChanges, got %v", sim.config)
	}

	stateDB, _ := sim.blockchain.State()
	bal := stateDB.GetBalance(testAddr)
	if bal.Cmp(expectedBal) != 0 {
		t.Errorf("expected balance for test address not received. expected: %v actual: %v", expectedBal, bal)
	}
}

func TestAdjustTime(t *testing.T) {
	sim := NewSimulatedBackend(
		core.GenesisAlloc{}, 10000000,
	)
	defer sim.Close()

	prevTime := sim.pendingBlock.Time()
	if err := sim.AdjustTime(time.Second); err != nil {
		t.Error(err)
	}
	newTime := sim.pendingBlock.Time()

	if newTime-prevTime != uint64(time.Second.Seconds()) {
		t.Errorf("adjusted time not equal to a second. prev: %v, new: %v", prevTime, newTime)
	}
}

func TestNewAdjustTimeFail(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)

	// Create tx and send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(0, testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}
	sim.SendTransaction(context.Background(), signedTx)
	// AdjustTime should fail on non-empty block
	if err := sim.AdjustTime(time.Second); err == nil {
		t.Error("Expected adjust time to error on non-empty block", err)
	}
	sim.Commit()

	prevTime := sim.pendingBlock.Time()
	if err := sim.AdjustTime(time.Minute); err != nil {
		t.Error(err)
	}
	newTime := sim.pendingBlock.Time()
	if newTime-prevTime != uint64(time.Minute.Seconds()) {
		t.Errorf("adjusted time not equal to a minute. prev: %v, new: %v", prevTime, newTime)
	}
	// Put a transaction after adjusting time
	tx2 := types.NewTransaction(1, testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx2, err := types.SignTx(tx2, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}
	sim.SendTransaction(context.Background(), signedTx2)
	sim.Commit()
	newTime = sim.pendingBlock.Time()
	if newTime-prevTime >= uint64(time.Minute.Seconds()) {
		t.Errorf("time adjusted, but shouldn't be: prev: %v, new: %v", prevTime, newTime)
	}
}

func TestBalanceAt(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	expectedBal := big.NewInt(10000000000000000)
	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	fmt.Println("BalanceAt")
	bal, err := sim.BalanceAt(bgCtx, testAddr, nil)
	if err != nil {
		t.Error(err)
	}

	if bal.Cmp(expectedBal) != 0 {
		t.Errorf("expected balance for test address not received. expected: %v actual: %v", expectedBal, bal)
	}
}

func TestBlockByHash(t *testing.T) {
	sim := NewSimulatedBackend(
		core.GenesisAlloc{}, 10000000,
	)
	defer sim.Close()
	bgCtx := context.Background()

	block, err := sim.BlockByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get recent block: %v", err)
	}
	blockByHash, err := sim.BlockByHash(bgCtx, block.Hash())
	if err != nil {
		t.Errorf("could not get recent block: %v", err)
	}

	if block.Hash() != blockByHash.Hash() {
		t.Errorf("did not get expected block")
	}
}

func TestBlockByNumber(t *testing.T) {
	sim := NewSimulatedBackend(
		core.GenesisAlloc{}, 10000000,
	)
	defer sim.Close()
	bgCtx := context.Background()

	block, err := sim.BlockByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get recent block: %v", err)
	}
	if block.NumberU64() != 0 {
		t.Errorf("did not get most recent block, instead got block number %v", block.NumberU64())
	}

	// create one block
	sim.Commit()

	block, err = sim.BlockByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get recent block: %v", err)
	}
	if block.NumberU64() != 1 {
		t.Errorf("did not get most recent block, instead got block number %v", block.NumberU64())
	}

	blockByNumber, err := sim.BlockByNumber(bgCtx, big.NewInt(1))
	if err != nil {
		t.Errorf("could not get block by number: %v", err)
	}
	if blockByNumber.Hash() != block.Hash() {
		t.Errorf("did not get the same block with height of 1 as before")
	}
}

func TestNonceAt(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	nonce, err := sim.NonceAt(bgCtx, testAddr, big.NewInt(0))
	if err != nil {
		t.Errorf("could not get nonce for test addr: %v", err)
	}

	if nonce != uint64(0) {
		t.Errorf("received incorrect nonce. expected 0, got %v", nonce)
	}

	// create a signed transaction to send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(nonce, testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}

	// send tx to simulated backend
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not add tx to pending block: %v", err)
	}
	sim.Commit()

	newNonce, err := sim.NonceAt(bgCtx, testAddr, big.NewInt(1))
	if err != nil {
		t.Errorf("could not get nonce for test addr: %v", err)
	}

	if newNonce != nonce+uint64(1) {
		t.Errorf("received incorrect nonce. expected 1, got %v", nonce)
	}
	// create some more blocks
	sim.Commit()
	// Check that we can get data for an older block/state
	newNonce, err = sim.NonceAt(bgCtx, testAddr, big.NewInt(1))
	if err != nil {
		t.Fatalf("could not get nonce for test addr: %v", err)
	}
	if newNonce != nonce+uint64(1) {
		t.Fatalf("received incorrect nonce. expected 1, got %v", nonce)
	}
}

func TestSendTransaction(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	// create a signed transaction to send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(uint64(0), testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}

	// send tx to simulated backend
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not add tx to pending block: %v", err)
	}
	sim.Commit()

	block, err := sim.BlockByNumber(bgCtx, big.NewInt(1))
	if err != nil {
		t.Errorf("could not get block at height 1: %v", err)
	}

	if signedTx.Hash() != block.Transactions()[0].Hash() {
		t.Errorf("did not commit sent transaction. expected hash %v got hash %v", block.Transactions()[0].Hash(), signedTx.Hash())
	}
}

func TestTransactionByHash(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := NewSimulatedBackend(
		core.GenesisAlloc{
			testAddr: {Balance: big.NewInt(10000000000000000)},
		}, 10000000,
	)
	defer sim.Close()
	bgCtx := context.Background()

	// create a signed transaction to send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(uint64(0), testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}

	// send tx to simulated backend
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not add tx to pending block: %v", err)
	}

	// ensure tx is committed pending
	receivedTx, pending, err := sim.TransactionByHash(bgCtx, signedTx.Hash())
	if err != nil {
		t.Errorf("could not get transaction by hash %v: %v", signedTx.Hash(), err)
	}
	if !pending {
		t.Errorf("expected transaction to be in pending state")
	}
	if receivedTx.Hash() != signedTx.Hash() {
		t.Errorf("did not received committed transaction. expected hash %v got hash %v", signedTx.Hash(), receivedTx.Hash())
	}

	sim.Commit()

	// ensure tx is not and committed pending
	receivedTx, pending, err = sim.TransactionByHash(bgCtx, signedTx.Hash())
	if err != nil {
		t.Errorf("could not get transaction by hash %v: %v", signedTx.Hash(), err)
	}
	if pending {
		t.Errorf("expected transaction to not be in pending state")
	}
	if receivedTx.Hash() != signedTx.Hash() {
		t.Errorf("did not received committed transaction. expected hash %v got hash %v", signedTx.Hash(), receivedTx.Hash())
	}
}

func TestEstimateGas(t *testing.T) {
	/*
		pragma solidity ^0.6.4;
		contract GasEstimation {
		    function PureRevert() public { revert(); }
		    function Revert() public { revert("revert reason");}
		    function OOG() public { for (uint i = 0; ; i++) {}}
		    function Assert() public { assert(false);}
		    function Valid() public {}
		}*/
	const contractAbi = "[{\"inputs\":[],\"name\":\"Assert\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"OOG\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"PureRevert\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"Revert\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[],\"name\":\"Valid\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"
	const contractBin = "0x60806040523480156100115760006000fd5b50610017565b61016e806100266000396000f3fe60806040523480156100115760006000fd5b506004361061005c5760003560e01c806350f6fe3414610062578063aa8b1d301461006c578063b9b046f914610076578063d8b9839114610080578063e09fface1461008a5761005c565b60006000fd5b61006a610094565b005b6100746100ad565b005b61007e6100b5565b005b6100886100c2565b005b610092610135565b005b6000600090505b5b808060010191505061009b565b505b565b60006000fd5b565b600015156100bf57fe5b5b565b6040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600d8152602001807f72657665727420726561736f6e0000000000000000000000000000000000000081526020015060200191505060405180910390fd5b565b5b56fea2646970667358221220345bbcbb1a5ecf22b53a78eaebf95f8ee0eceff6d10d4b9643495084d2ec934a64736f6c63430006040033"

	key, _ := gmsm.GenerateKey()
	addr := gmsm.PubkeyToAddress(key.PublicKey)
	opts, _ := bind.NewKeyedTransactorWithChainID(key, big.NewInt(1337))

	sim := NewSimulatedBackend(core.GenesisAlloc{addr: {Balance: big.NewInt(params.Ether)}}, 10000000)
	defer sim.Close()

	parsed, _ := abi.JSON(strings.NewReader(contractAbi))
	contractAddr, _, _, _ := bind.DeployContract(opts, parsed, common.FromHex(contractBin), sim)
	sim.Commit()

	var cases = []struct {
		name        string
		message     ethereum.CallMsg
		expect      uint64
		expectError error
		expectData  interface{}
	}{
		{"plain transfer(valid)", ethereum.CallMsg{
			From:     addr,
			To:       &addr,
			Gas:      0,
			GasPrice: big.NewInt(0),
			Value:    big.NewInt(1),
			Data:     nil,
		}, params.TxGas, nil, nil},

		{"plain transfer(invalid)", ethereum.CallMsg{
			From:     addr,
			To:       &contractAddr,
			Gas:      0,
			GasPrice: big.NewInt(0),
			Value:    big.NewInt(1),
			Data:     nil,
		}, 0, errors.New("execution reverted"), nil},

		{"Revert", ethereum.CallMsg{
			From:     addr,
			To:       &contractAddr,
			Gas:      0,
			GasPrice: big.NewInt(0),
			Value:    nil,
			Data:     common.Hex2Bytes("d8b98391"),
		}, 0, errors.New("execution reverted: revert reason"), "0x08c379a00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000000d72657665727420726561736f6e00000000000000000000000000000000000000"},

		{"PureRevert", ethereum.CallMsg{
			From:     addr,
			To:       &contractAddr,
			Gas:      0,
			GasPrice: big.NewInt(0),
			Value:    nil,
			Data:     common.Hex2Bytes("aa8b1d30"),
		}, 0, errors.New("execution reverted"), nil},

		{"OOG", ethereum.CallMsg{
			From:     addr,
			To:       &contractAddr,
			Gas:      100000,
			GasPrice: big.NewInt(0),
			Value:    nil,
			Data:     common.Hex2Bytes("50f6fe34"),
		}, 0, errors.New("gas required exceeds allowance (100000)"), nil},

		{"Assert", ethereum.CallMsg{
			From:     addr,
			To:       &contractAddr,
			Gas:      100000,
			GasPrice: big.NewInt(0),
			Value:    nil,
			Data:     common.Hex2Bytes("b9b046f9"),
		}, 0, errors.New("invalid opcode: INVALID"), nil},

		{"Valid", ethereum.CallMsg{
			From:     addr,
			To:       &contractAddr,
			Gas:      100000,
			GasPrice: big.NewInt(0),
			Value:    nil,
			Data:     common.Hex2Bytes("e09fface"),
		}, 21275, nil, nil},
	}
	for _, c := range cases {
		fmt.Println(c.name)
		got, err := sim.EstimateGas(context.Background(), c.message)
		if c.expectError != nil {
			t.Log("error mssage: ", err)
			if err == nil {
				t.Fatalf("Expect error, got nil")
			}
			if c.expectError.Error() != err.Error() {
				t.Fatalf("Expect error, want %v, got %v", c.expectError, err)
			}
			if c.expectData != nil {
				if err, ok := err.(*revertError); !ok {
					t.Fatalf("Expect revert error, got %T", err)
				} else if !reflect.DeepEqual(err.ErrorData(), c.expectData) {
					t.Fatalf("Error data mismatch, want %v, got %v", c.expectData, err.ErrorData())
				}
			}
			continue
		}
		if got != c.expect {
			t.Fatalf("Gas estimation mismatch, want %d, got %d", c.expect, got)
		}
	}
}

func TestEstimateGasWithPrice(t *testing.T) {
	key, _ := gmsm.GenerateKey()
	addr := gmsm.PubkeyToAddress(key.PublicKey)

	sim := NewSimulatedBackend(core.GenesisAlloc{addr: {Balance: big.NewInt(params.Ether*2 + 2e17)}}, 10000000)
	defer sim.Close()

	recipient := common.HexToAddress("deadbeef")
	var cases = []struct {
		name        string
		message     ethereum.CallMsg
		expect      uint64
		expectError error
	}{
		{"EstimateWithoutPrice", ethereum.CallMsg{
			From:     addr,
			To:       &recipient,
			Gas:      0,
			GasPrice: big.NewInt(0),
			Value:    big.NewInt(100000000000),
			Data:     nil,
		}, 21000, nil},

		{"EstimateWithPrice", ethereum.CallMsg{
			From:     addr,
			To:       &recipient,
			Gas:      0,
			GasPrice: big.NewInt(100000000000),
			Value:    big.NewInt(100000000000),
			Data:     nil,
		}, 21000, nil},

		{"EstimateWithVeryHighPrice", ethereum.CallMsg{
			From:     addr,
			To:       &recipient,
			Gas:      0,
			GasPrice: big.NewInt(1e14), // gascost = 2.1ether
			Value:    big.NewInt(1e17), // the remaining balance for fee is 2.1ether
			Data:     nil,
		}, 21000, nil},

		{"EstimateWithSuperhighPrice", ethereum.CallMsg{
			From:     addr,
			To:       &recipient,
			Gas:      0,
			GasPrice: big.NewInt(2e14), // gascost = 4.2ether
			Value:    big.NewInt(100000000000),
			Data:     nil,
		}, 21000, errors.New("gas required exceeds allowance (10999)")}, // 10999=(2.2ether-1000wei)/(2e14)

		{"EstimateEIP1559WithHighFees", ethereum.CallMsg{
			From:      addr,
			To:        &addr,
			Gas:       0,
			GasFeeCap: big.NewInt(1e14), // maxgascost = 2.1ether
			GasTipCap: big.NewInt(1),
			Value:     big.NewInt(1e17), // the remaining balance for fee is 2.1ether
			Data:      nil,
		}, params.TxGas, nil},

		{"EstimateEIP1559WithSuperHighFees", ethereum.CallMsg{
			From:      addr,
			To:        &addr,
			Gas:       0,
			GasFeeCap: big.NewInt(1e14), // maxgascost = 2.1ether
			GasTipCap: big.NewInt(1),
			Value:     big.NewInt(1e17 + 1), // the remaining balance for fee is 2.1ether
			Data:      nil,
		}, params.TxGas, errors.New("gas required exceeds allowance (20999)")}, // 20999=(2.2ether-0.1ether-1wei)/(1e14)
	}
	for i, c := range cases {
		got, err := sim.EstimateGas(context.Background(), c.message)
		if c.expectError != nil {
			if err == nil {
				t.Fatalf("test %d: expect error, got nil", i)
			}
			if c.expectError.Error() != err.Error() {
				t.Fatalf("test %d: expect error, want %v, got %v", i, c.expectError, err)
			}
			continue
		}
		if c.expectError == nil && err != nil {
			t.Fatalf("test %d: didn't expect error, got %v", i, err)
		}
		if got != c.expect {
			t.Fatalf("test %d: gas estimation mismatch, want %d, got %d", i, c.expect, got)
		}
	}
}

func TestHeaderByHash(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	header, err := sim.HeaderByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get recent block: %v", err)
	}
	headerByHash, err := sim.HeaderByHash(bgCtx, header.Hash())
	if err != nil {
		t.Errorf("could not get recent block: %v", err)
	}

	if header.Hash() != headerByHash.Hash() {
		t.Errorf("did not get expected block")
	}
}

func TestHeaderByNumber(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	latestBlockHeader, err := sim.HeaderByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get header for tip of chain: %v", err)
	}
	if latestBlockHeader == nil {
		t.Errorf("received a nil block header")
	} else if latestBlockHeader.Number.Uint64() != uint64(0) {
		t.Errorf("expected block header number 0, instead got %v", latestBlockHeader.Number.Uint64())
	}

	sim.Commit()

	latestBlockHeader, err = sim.HeaderByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get header for blockheight of 1: %v", err)
	}

	blockHeader, err := sim.HeaderByNumber(bgCtx, big.NewInt(1))
	if err != nil {
		t.Errorf("could not get header for blockheight of 1: %v", err)
	}

	if blockHeader.Hash() != latestBlockHeader.Hash() {
		t.Errorf("block header and latest block header are not the same")
	}
	if blockHeader.Number.Int64() != int64(1) {
		t.Errorf("did not get blockheader for block 1. instead got block %v", blockHeader.Number.Int64())
	}

	block, err := sim.BlockByNumber(bgCtx, big.NewInt(1))
	if err != nil {
		t.Errorf("could not get block for blockheight of 1: %v", err)
	}

	if block.Hash() != blockHeader.Hash() {
		t.Errorf("block hash and block header hash do not match. expected %v, got %v", block.Hash(), blockHeader.Hash())
	}
}

func TestTransactionCount(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()
	currentBlock, err := sim.BlockByNumber(bgCtx, nil)
	if err != nil || currentBlock == nil {
		t.Error("could not get current block")
	}

	count, err := sim.TransactionCount(bgCtx, currentBlock.Hash())
	if err != nil {
		t.Error("could not get current block's transaction count")
	}

	if count != 0 {
		t.Errorf("expected transaction count of %v does not match actual count of %v", 0, count)
	}
	// create a signed transaction to send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(uint64(0), testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}

	// send tx to simulated backend
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not add tx to pending block: %v", err)
	}

	sim.Commit()

	lastBlock, err := sim.BlockByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get header for tip of chain: %v", err)
	}

	count, err = sim.TransactionCount(bgCtx, lastBlock.Hash())
	if err != nil {
		t.Error("could not get current block's transaction count")
	}

	if count != 1 {
		t.Errorf("expected transaction count of %v does not match actual count of %v", 1, count)
	}
}

func TestTransactionInBlock(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	transaction, err := sim.TransactionInBlock(bgCtx, sim.pendingBlock.Hash(), uint(0))
	if err == nil && err != errTransactionDoesNotExist {
		t.Errorf("expected a transaction does not exist error to be received but received %v", err)
	}
	if transaction != nil {
		t.Errorf("expected transaction to be nil but received %v", transaction)
	}

	// expect pending nonce to be 0 since account has not been used
	pendingNonce, err := sim.PendingNonceAt(bgCtx, testAddr)
	if err != nil {
		t.Errorf("did not get the pending nonce: %v", err)
	}

	if pendingNonce != uint64(0) {
		t.Errorf("expected pending nonce of 0 got %v", pendingNonce)
	}
	// create a signed transaction to send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(uint64(0), testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}

	// send tx to simulated backend
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not add tx to pending block: %v", err)
	}

	sim.Commit()

	lastBlock, err := sim.BlockByNumber(bgCtx, nil)
	if err != nil {
		t.Errorf("could not get header for tip of chain: %v", err)
	}

	transaction, err = sim.TransactionInBlock(bgCtx, lastBlock.Hash(), uint(1))
	if err == nil && err != errTransactionDoesNotExist {
		t.Errorf("expected a transaction does not exist error to be received but received %v", err)
	}
	if transaction != nil {
		t.Errorf("expected transaction to be nil but received %v", transaction)
	}

	transaction, err = sim.TransactionInBlock(bgCtx, lastBlock.Hash(), uint(0))
	if err != nil {
		t.Errorf("could not get transaction in the lastest block with hash %v: %v", lastBlock.Hash().String(), err)
	}

	if signedTx.Hash().String() != transaction.Hash().String() {
		t.Errorf("received transaction that did not match the sent transaction. expected hash %v, got hash %v", signedTx.Hash().String(), transaction.Hash().String())
	}
}

func TestPendingNonceAt(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	// expect pending nonce to be 0 since account has not been used
	pendingNonce, err := sim.PendingNonceAt(bgCtx, testAddr)
	if err != nil {
		t.Errorf("did not get the pending nonce: %v", err)
	}

	if pendingNonce != uint64(0) {
		t.Errorf("expected pending nonce of 0 got %v", pendingNonce)
	}

	// create a signed transaction to send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(uint64(0), testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}

	// send tx to simulated backend
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not add tx to pending block: %v", err)
	}

	// expect pending nonce to be 1 since account has submitted one transaction
	pendingNonce, err = sim.PendingNonceAt(bgCtx, testAddr)
	if err != nil {
		t.Errorf("did not get the pending nonce: %v", err)
	}

	if pendingNonce != uint64(1) {
		t.Errorf("expected pending nonce of 1 got %v", pendingNonce)
	}

	// make a new transaction with a nonce of 1
	tx = types.NewTransaction(uint64(1), testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err = types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not send tx: %v", err)
	}

	// expect pending nonce to be 2 since account now has two transactions
	pendingNonce, err = sim.PendingNonceAt(bgCtx, testAddr)
	if err != nil {
		t.Errorf("did not get the pending nonce: %v", err)
	}

	if pendingNonce != uint64(2) {
		t.Errorf("expected pending nonce of 2 got %v", pendingNonce)
	}
}

func TestTransactionReceipt(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)

	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	// create a signed transaction to send
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	tx := types.NewTransaction(uint64(0), testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	signedTx, err := types.SignTx(tx, types.HomesteadSigner{}, testKey)
	if err != nil {
		t.Errorf("could not sign tx: %v", err)
	}

	// send tx to simulated backend
	err = sim.SendTransaction(bgCtx, signedTx)
	if err != nil {
		t.Errorf("could not add tx to pending block: %v", err)
	}
	sim.Commit()

	receipt, err := sim.TransactionReceipt(bgCtx, signedTx.Hash())
	if err != nil {
		t.Errorf("could not get transaction receipt: %v", err)
	}

	if receipt.ContractAddress != testAddr && receipt.TxHash != signedTx.Hash() {
		t.Errorf("received receipt is not correct: %v", receipt)
	}
}

func TestSuggestGasPrice(t *testing.T) {
	sim := NewSimulatedBackend(
		core.GenesisAlloc{},
		10000000,
	)
	defer sim.Close()
	bgCtx := context.Background()
	gasPrice, err := sim.SuggestGasPrice(bgCtx)
	if err != nil {
		t.Errorf("could not get gas price: %v", err)
	}
	if gasPrice.Uint64() != sim.pendingBlock.Header().BaseFee.Uint64() {
		t.Errorf("gas price was not expected value of %v. actual: %v", sim.pendingBlock.Header().BaseFee.Uint64(), gasPrice.Uint64())
	}
}

func TestPendingCodeAt(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()
	code, err := sim.CodeAt(bgCtx, testAddr, nil)
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	if len(code) != 0 {
		t.Errorf("got code for account that does not have contract code")
	}

	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	auth, _ := bind.NewKeyedTransactorWithChainID(testKey, big.NewInt(0))
	contractAddr, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(abiBin), sim)
	if err != nil {
		t.Errorf("could not deploy contract: %v tx: %v contract: %v", err, tx, contract)
	}

	code, err = sim.PendingCodeAt(bgCtx, contractAddr)
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	if len(code) == 0 {
		t.Errorf("did not get code for account that has contract code")
	}
	// ensure code received equals code deployed
	if !bytes.Equal(code, common.FromHex(deployedCode)) {
		t.Errorf("code received did not match expected deployed code:\n expected %v\n actual %v", common.FromHex(deployedCode), code)
	}
}

func TestCodeAt(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	p := gmsm.CompressPubkey(&testKey.PublicKey)
	fmt.Println(len(p), hex.EncodeToString(p))
	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()
	code, err := sim.CodeAt(bgCtx, testAddr, nil)
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	if len(code) != 0 {
		t.Errorf("got code for account that does not have contract code")
	}

	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	auth, _ := bind.NewKeyedTransactorWithChainID(testKey, big.NewInt(0))
	contractAddr, tx, contract, err := bind.DeployContract(auth, parsed, common.FromHex(abiBin), sim)
	if err != nil {
		t.Errorf("could not deploy contract: %v tx: %v contract: %v", err, tx, contract)
	}

	sim.Commit()
	code, err = sim.CodeAt(bgCtx, contractAddr, nil)
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	if len(code) == 0 {
		t.Errorf("did not get code for account that has contract code")
	}
	// ensure code received equals code deployed
	if !bytes.Equal(code, common.FromHex(deployedCode)) {
		t.Errorf("code received did not match expected deployed code:\n expected %v\n actual %v", common.FromHex(deployedCode), code)
	}
}

// When receive("X") is called with sender 0x00... and value 1, it produces this tx receipt:
//
//	receipt{status=1 cgas=23949 bloom=00000000004000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000040200000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000 logs=[log: b6818c8064f645cd82d99b59a1a267d6d61117ef [75fd880d39c1daf53b6547ab6cb59451fc6452d27caa90e5b6649dd8293b9eed] 000000000000000000000000376c47978271565f56deb45495afa69e59c16ab200000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000000000000000060000000000000000000000000000000000000000000000000000000000000000158 9ae378b6d4409eada347a5dc0c180f186cb62dc68fcc0f043425eb917335aa28 0 95d429d309bb9d753954195fe2d69bd140b4ae731b9b5b605c34323de162cf00 0]}
func TestPendingAndCallContract(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	parsed, err := abi.JSON(strings.NewReader(abiJSON))
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	contractAuth, _ := bind.NewKeyedTransactorWithChainID(testKey, big.NewInt(0))
	addr, _, _, err := bind.DeployContract(contractAuth, parsed, common.FromHex(abiBin), sim)
	if err != nil {
		t.Errorf("could not deploy contract: %v", err)
	}

	input, err := parsed.Pack("receive", []byte("X"))
	if err != nil {
		t.Errorf("could not pack receive function on contract: %v", err)
	}

	// make sure you can call the contract in pending state
	res, err := sim.PendingCallContract(bgCtx, ethereum.CallMsg{
		From: testAddr,
		To:   &addr,
		Data: input,
	})
	if err != nil {
		t.Errorf("could not call receive method on contract: %v", err)
	}
	if len(res) == 0 {
		t.Errorf("result of contract call was empty: %v", res)
	}

	// while comparing against the byte array is more exact, also compare against the human readable string for readability
	if !bytes.Equal(res, expectedReturn) || !strings.Contains(string(res), "hello world") {
		t.Errorf("response from calling contract was expected to be 'hello world' instead received %v", string(res))
	}

	sim.Commit()

	// make sure you can call the contract
	res, err = sim.CallContract(bgCtx, ethereum.CallMsg{
		From: testAddr,
		To:   &addr,
		Data: input,
	}, nil)
	if err != nil {
		t.Errorf("could not call receive method on contract: %v", err)
	}
	if len(res) == 0 {
		t.Errorf("result of contract call was empty: %v", res)
	}

	if !bytes.Equal(res, expectedReturn) || !strings.Contains(string(res), "hello world") {
		t.Errorf("response from calling contract was expected to be 'hello world' instead received %v", string(res))
	}
}

// This test is based on the following contract:
/*
contract Reverter {
    function revertString() public pure{
        require(false, "some error");
    }
    function revertNoString() public pure {
        require(false, "");
    }
    function revertASM() public pure {
        assembly {
            revert(0x0, 0x0)
        }
    }
    function noRevert() public pure {
        assembly {
            // Assembles something that looks like require(false, "some error") but is not reverted
            mstore(0x0, 0x08c379a000000000000000000000000000000000000000000000000000000000)
            mstore(0x4, 0x0000000000000000000000000000000000000000000000000000000000000020)
            mstore(0x24, 0x000000000000000000000000000000000000000000000000000000000000000a)
            mstore(0x44, 0x736f6d65206572726f7200000000000000000000000000000000000000000000)
            return(0x0, 0x64)
        }
    }
}*/
func TestCallContractRevert(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)
	defer sim.Close()
	bgCtx := context.Background()

	reverterABI := `[{"inputs": [],"name": "noRevert","outputs": [],"stateMutability": "pure","type": "function"},{"inputs": [],"name": "revertASM","outputs": [],"stateMutability": "pure","type": "function"},{"inputs": [],"name": "revertNoString","outputs": [],"stateMutability": "pure","type": "function"},{"inputs": [],"name": "revertString","outputs": [],"stateMutability": "pure","type": "function"}]`
	reverterBin := "608060405234801561001057600080fd5b506101d3806100206000396000f3fe608060405234801561001057600080fd5b506004361061004c5760003560e01c80634b409e01146100515780639b340e361461005b5780639bd6103714610065578063b7246fc11461006f575b600080fd5b610059610079565b005b6100636100ca565b005b61006d6100cf565b005b610077610145565b005b60006100c8576040517f08c379a0000000000000000000000000000000000000000000000000000000008152600401808060200182810382526000815260200160200191505060405180910390fd5b565b600080fd5b6000610143576040517f08c379a000000000000000000000000000000000000000000000000000000000815260040180806020018281038252600a8152602001807f736f6d65206572726f720000000000000000000000000000000000000000000081525060200191505060405180910390fd5b565b7f08c379a0000000000000000000000000000000000000000000000000000000006000526020600452600a6024527f736f6d65206572726f720000000000000000000000000000000000000000000060445260646000f3fea2646970667358221220cdd8af0609ec4996b7360c7c780bad5c735740c64b1fffc3445aa12d37f07cb164736f6c63430006070033"

	parsed, err := abi.JSON(strings.NewReader(reverterABI))
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	contractAuth, _ := bind.NewKeyedTransactorWithChainID(testKey, big.NewInt(1337))
	addr, _, _, err := bind.DeployContract(contractAuth, parsed, common.FromHex(reverterBin), sim)
	if err != nil {
		t.Errorf("could not deploy contract: %v", err)
	}

	inputs := make(map[string]interface{}, 3)
	inputs["revertASM"] = nil
	inputs["revertNoString"] = ""
	inputs["revertString"] = "some error"

	call := make([]func([]byte) ([]byte, error), 2)
	call[0] = func(input []byte) ([]byte, error) {
		return sim.PendingCallContract(bgCtx, ethereum.CallMsg{
			From: testAddr,
			To:   &addr,
			Data: input,
		})
	}
	call[1] = func(input []byte) ([]byte, error) {
		return sim.CallContract(bgCtx, ethereum.CallMsg{
			From: testAddr,
			To:   &addr,
			Data: input,
		}, nil)
	}

	// Run pending calls then commit
	for _, cl := range call {
		for key, val := range inputs {
			input, err := parsed.Pack(key)
			if err != nil {
				t.Errorf("could not pack %v function on contract: %v", key, err)
			}

			res, err := cl(input)
			if err == nil {
				t.Errorf("call to %v was not reverted", key)
			}
			if res != nil {
				t.Errorf("result from %v was not nil: %v", key, res)
			}
			if val != nil {
				rerr, ok := err.(*revertError)
				if !ok {
					t.Errorf("expect revert error")
				}
				if rerr.Error() != "execution reverted: "+val.(string) {
					t.Errorf("error was malformed: got %v want %v", rerr.Error(), val)
				}
			} else {
				// revert(0x0,0x0)
				if err.Error() != "execution reverted" {
					t.Errorf("error was malformed: got %v want %v", err, "execution reverted")
				}
			}
		}
		input, err := parsed.Pack("noRevert")
		if err != nil {
			t.Errorf("could not pack noRevert function on contract: %v", err)
		}
		res, err := cl(input)
		if err != nil {
			t.Error("call to noRevert was reverted")
		}
		if res == nil {
			t.Errorf("result from noRevert was nil")
		}
		sim.Commit()
	}
}

// TestFork check that the chain length after a reorg is correct.
// Steps:
//  1. Save the current block which will serve as parent for the fork.
//  2. Mine n blocks with n ∈ [0, 20].
//  3. Assert that the chain length is n.
//  4. Fork by using the parent block as ancestor.
//  5. Mine n+1 blocks which should trigger a reorg.
//  6. Assert that the chain length is n+1.
//     Since Commit() was called 2n+1 times in total,
//     having a chain length of just n+1 means that a reorg occurred.
func TestFork(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)
	defer sim.Close()
	// 1.
	parent := sim.blockchain.CurrentBlock()
	// 2.
	n := int(rand.Int31n(21))
	for i := 0; i < n; i++ {
		sim.Commit()
	}
	// 3.
	if sim.blockchain.CurrentBlock().NumberU64() != uint64(n) {
		t.Error("wrong chain length")
	}
	// 4.
	sim.Fork(context.Background(), parent.Hash())
	// 5.
	for i := 0; i < n+1; i++ {
		sim.Commit()
	}
	// 6.
	if sim.blockchain.CurrentBlock().NumberU64() != uint64(n+1) {
		t.Error("wrong chain length")
	}
}

/*
Example contract to test event emission:

pragma solidity >=0.7.0 <0.9.0;

	contract Callable {
	    event Called();
	    function Call() public { emit Called(); }
	}
*/
const callableAbi = "[{\"anonymous\":false,\"inputs\":[],\"name\":\"Called\",\"type\":\"event\"},{\"inputs\":[],\"name\":\"Call\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]"

const callableBin = "6080604052348015600f57600080fd5b5060998061001e6000396000f3fe6080604052348015600f57600080fd5b506004361060285760003560e01c806334e2292114602d575b600080fd5b60336035565b005b7f81fab7a4a0aa961db47eefc81f143a5220e8c8495260dd65b1356f1d19d3c7b860405160405180910390a156fea2646970667358221220029436d24f3ac598ceca41d4d712e13ced6d70727f4cdc580667de66d2f51d8b64736f6c63430008010033"

// TestForkLogsReborn check that the simulated reorgs
// correctly remove and reborn logs.
// Steps:
//  1. Deploy the Callable contract.
//  2. Set up an event subscription.
//  3. Save the current block which will serve as parent for the fork.
//  4. Send a transaction.
//  5. Check that the event was included.
//  6. Fork by using the parent block as ancestor.
//  7. Mine two blocks to trigger a reorg.
//  8. Check that the event was removed.
//  9. Re-send the transaction and mine a block.
//
// 10. Check that the event was reborn.
func TestForkLogsReborn(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)
	defer sim.Close()
	// 1.
	parsed, _ := abi.JSON(strings.NewReader(callableAbi))
	auth, _ := bind.NewKeyedTransactorWithChainID(testKey, big.NewInt(1337))
	_, _, contract, err := bind.DeployContract(auth, parsed, common.FromHex(callableBin), sim)
	if err != nil {
		t.Errorf("deploying contract: %v", err)
	}
	sim.Commit()
	// 2.
	logs, sub, err := contract.WatchLogs(nil, "Called")
	if err != nil {
		t.Errorf("watching logs: %v", err)
	}
	defer sub.Unsubscribe()
	// 3.
	parent := sim.blockchain.CurrentBlock()
	// 4.
	tx, err := contract.Transact(auth, "Call")
	if err != nil {
		t.Errorf("transacting: %v", err)
	}
	sim.Commit()
	// 5.
	log := <-logs
	if log.TxHash != tx.Hash() {
		t.Error("wrong event tx hash")
	}
	if log.Removed {
		t.Error("Event should be included")
	}
	// 6.
	if err := sim.Fork(context.Background(), parent.Hash()); err != nil {
		t.Errorf("forking: %v", err)
	}
	// 7.
	sim.Commit()
	sim.Commit()
	// 8.
	log = <-logs
	if log.TxHash != tx.Hash() {
		t.Error("wrong event tx hash")
	}
	if !log.Removed {
		t.Error("Event should be removed")
	}
	// 9.
	if err := sim.SendTransaction(context.Background(), tx); err != nil {
		t.Errorf("sending transaction: %v", err)
	}
	sim.Commit()
	// 10.
	log = <-logs
	if log.TxHash != tx.Hash() {
		t.Error("wrong event tx hash")
	}
	if log.Removed {
		t.Error("Event should be included")
	}
}

// TestForkResendTx checks that re-sending a TX after a fork
// is possible and does not cause a "nonce mismatch" panic.
// Steps:
//  1. Save the current block which will serve as parent for the fork.
//  2. Send a transaction.
//  3. Check that the TX is included in block 1.
//  4. Fork by using the parent block as ancestor.
//  5. Mine a block, Re-send the transaction and mine another one.
//  6. Check that the TX is now included in block 2.
func TestForkResendTx(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)
	defer sim.Close()
	// 1.
	parent := sim.blockchain.CurrentBlock()
	// 2.
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))

	_tx := types.NewTransaction(0, testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	tx, _ := types.SignTx(_tx, types.HomesteadSigner{}, testKey)
	sim.SendTransaction(context.Background(), tx)
	sim.Commit()
	// 3.
	receipt, _ := sim.TransactionReceipt(context.Background(), tx.Hash())
	if h := receipt.BlockNumber.Uint64(); h != 1 {
		t.Errorf("TX included in wrong block: %d", h)
	}
	// 4.
	if err := sim.Fork(context.Background(), parent.Hash()); err != nil {
		t.Errorf("forking: %v", err)
	}
	// 5.
	sim.Commit()
	if err := sim.SendTransaction(context.Background(), tx); err != nil {
		t.Errorf("sending transaction: %v", err)
	}
	sim.Commit()
	// 6.
	receipt, _ = sim.TransactionReceipt(context.Background(), tx.Hash())
	if h := receipt.BlockNumber.Uint64(); h != 2 {
		t.Errorf("TX included in wrong block: %d", h)
	}
}

func TestCommitReturnValue(t *testing.T) {
	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	sim := simTestBackend(testAddr)
	defer sim.Close()

	startBlockHeight := sim.blockchain.CurrentBlock().NumberU64()

	// Test if Commit returns the correct block hash
	h1 := sim.Commit()
	if h1 != sim.blockchain.CurrentBlock().Hash() {
		t.Error("Commit did not return the hash of the last block.")
	}

	// Create a block in the original chain (containing a transaction to force different block hashes)
	head, _ := sim.HeaderByNumber(context.Background(), nil) // Should be child's, good enough
	gasPrice := new(big.Int).Add(head.BaseFee, big.NewInt(1))
	_tx := types.NewTransaction(0, testAddr, big.NewInt(1000), params.TxGas, gasPrice, nil)
	tx, _ := types.SignTx(_tx, types.HomesteadSigner{}, testKey)
	sim.SendTransaction(context.Background(), tx)
	h2 := sim.Commit()

	// Create another block in the original chain
	sim.Commit()

	// Fork at the first bock
	if err := sim.Fork(context.Background(), h1); err != nil {
		t.Errorf("forking: %v", err)
	}

	// Test if Commit returns the correct block hash after the reorg
	h2fork := sim.Commit()
	if h2 == h2fork {
		t.Error("The block in the fork and the original block are the same block!")
	}
	if sim.blockchain.GetHeader(h2fork, startBlockHeight+2) == nil {
		t.Error("Could not retrieve the just created block (side-chain)")
	}
}

func TestShotsnap(t *testing.T) {
	db := rawdb.NewMemoryDatabase()
	stateCache := state.NewDatabaseWithConfig(db, &trie.Config{
		Cache:     256,
		Journal:   "triecache",
		Preimages: true,
	})
	SnapshotLimit := 256

	testAddr := gmsm.PubkeyToAddress(testKey.PublicKey)
	alloc := core.GenesisAlloc{
		testAddr: {Balance: big.NewInt(10000000000000000)},
	}
	genesis := core.Genesis{Config: params.AllEthashProtocolChanges, GasLimit: 10000000, Alloc: alloc}
	block := genesis.MustCommit(db)
	root := block.Root()

	snaps, err := snapshot.New(db, stateCache.TrieDB(), SnapshotLimit, root, false, true, true)
	if err != nil {
		t.Fatal(err)
	}

	hasher := sm3.New()
	key := gmsm.HashData(hasher, testAddr.Bytes())
	snap := snaps.Snapshot(root)
	account, err := snap.Account(key)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("account balance: ", account.Balance)
}

func TestCallContract(t *testing.T) {
	const abitest = `[
	{
		"inputs": [],
		"name": "i",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "n",
				"type": "uint256"
			}
		],
		"name": "test",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`
	const bintest = "6080604052604060005534801561001557600080fd5b506101ee806100256000396000f3fe608060405234801561001057600080fd5b50600436106100415760003560e01c806329e99f071461004657806367e404ce14610076578063e5aa3d5814610094575b600080fd5b610060600480360381019061005b91906100e8565b6100b2565b60405161006d919061014a565b60405180910390f35b61007e6100c5565b60405161008b919061012f565b60405180910390f35b61009c6100cd565b6040516100a9919061014a565b60405180910390f35b6000816000819055506000549050919050565b600033905090565b60005481565b6000813590506100e2816101a1565b92915050565b6000602082840312156100fa57600080fd5b6000610108848285016100d3565b91505092915050565b61011a81610165565b82525050565b61012981610197565b82525050565b60006020820190506101446000830184610111565b92915050565b600060208201905061015f6000830184610120565b92915050565b600061017082610177565b9050919050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000819050919050565b6101aa81610197565b81146101b557600080fd5b5056fea26469706673582212202200d1ddc3858b28ecd57625c3b8ba61d57d7e14742ae1ef657e0e08bd9c9f0d64736f6c63430008020033"
	priKey, _ := gmsm.HexToSM2("39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d")
	t.Log("公钥：", hex.EncodeToString(gmsm.CompressPubkey(&priKey.PublicKey)))
	testAddr := gmsm.PubkeyToAddress(priKey.PublicKey)
	t.Log("地址：", testAddr)
	sim := simTestBackend(testAddr)
	defer sim.Close()

	parsed, err := abi.JSON(strings.NewReader(abitest))
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	contractAuth, err := bind.NewKeyedTransactorWithChainID(priKey, big.NewInt(0))
	addr, _, _, err := bind.DeployContract(contractAuth, parsed, common.FromHex(bintest), sim)
	if err != nil {
		t.Errorf("could not deploy contract: %v", err)
	}
	fmt.Println("deploy contract address: ", addr)
	fmt.Println("===========================================================================================================")

	//addr = common.HexToAddress("0x1cCc0D653B8674b24E1413c6795F1456cD4841a9")
	//no.2 step -> PendingCallContract
	res, err := callContract(sim, ethereum.CallMsg{
		From:      testAddr,
		To:        &addr,
		Data:      common.Hex2Bytes("29e99f070000000000000000000000000000000000000000000000000000000000000002"),
		GasFeeCap: new(big.Int),
		GasTipCap: new(big.Int),
		Gas:       50000000,
		GasPrice:  new(big.Int),
		Value:     new(big.Int),
	})
	if err != nil {
		t.Errorf("could not call receive method on contract: %v", err)
	}
	fmt.Println(hex.EncodeToString(res))
}

func callContract(b *SimulatedBackend, call ethereum.CallMsg) ([]byte, error) {
	block := b.pendingBlock
	stateDB := b.pendingState

	msg := callMsg{call}
	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(block.Header(), b.blockchain, nil)

	vmEnv := vm.NewEVM(evmContext, txContext, stateDB, b.config, vm.Config{NoBaseFee: true})
	gasPool := new(core.GasPool).AddGas(math.MaxUint64)
	res, err := core.NewStateTransition(vmEnv, msg, gasPool).TransitionDb()
	return res.Return(), err
}

func TestCallERC20(t *testing.T) {
	const abitest = `[
	{
		"inputs": [],
		"stateMutability": "nonpayable",
		"type": "constructor"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "allowance",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "needed",
				"type": "uint256"
			}
		],
		"name": "ERC20InsufficientAllowance",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "sender",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "balance",
				"type": "uint256"
			},
			{
				"internalType": "uint256",
				"name": "needed",
				"type": "uint256"
			}
		],
		"name": "ERC20InsufficientBalance",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "approver",
				"type": "address"
			}
		],
		"name": "ERC20InvalidApprover",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "receiver",
				"type": "address"
			}
		],
		"name": "ERC20InvalidReceiver",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "sender",
				"type": "address"
			}
		],
		"name": "ERC20InvalidSender",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			}
		],
		"name": "ERC20InvalidSpender",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "owner",
				"type": "address"
			}
		],
		"name": "OwnableInvalidOwner",
		"type": "error"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "account",
				"type": "address"
			}
		],
		"name": "OwnableUnauthorizedAccount",
		"type": "error"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "spender",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "Approval",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "previousOwner",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "newOwner",
				"type": "address"
			}
		],
		"name": "OwnershipTransferred",
		"type": "event"
	},
	{
		"anonymous": false,
		"inputs": [
			{
				"indexed": true,
				"internalType": "address",
				"name": "from",
				"type": "address"
			},
			{
				"indexed": true,
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"indexed": false,
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "Transfer",
		"type": "event"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "owner",
				"type": "address"
			},
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			}
		],
		"name": "allowance",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "spender",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "approve",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "account",
				"type": "address"
			}
		],
		"name": "balanceOf",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "burn",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "account",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "burnFrom",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "decimals",
		"outputs": [
			{
				"internalType": "uint8",
				"name": "",
				"type": "uint8"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "amount",
				"type": "uint256"
			}
		],
		"name": "mint",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "name",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "owner",
		"outputs": [
			{
				"internalType": "address",
				"name": "",
				"type": "address"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "renounceOwnership",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "symbol",
		"outputs": [
			{
				"internalType": "string",
				"name": "",
				"type": "string"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [],
		"name": "totalSupply",
		"outputs": [
			{
				"internalType": "uint256",
				"name": "",
				"type": "uint256"
			}
		],
		"stateMutability": "view",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "transfer",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "from",
				"type": "address"
			},
			{
				"internalType": "address",
				"name": "to",
				"type": "address"
			},
			{
				"internalType": "uint256",
				"name": "value",
				"type": "uint256"
			}
		],
		"name": "transferFrom",
		"outputs": [
			{
				"internalType": "bool",
				"name": "",
				"type": "bool"
			}
		],
		"stateMutability": "nonpayable",
		"type": "function"
	},
	{
		"inputs": [
			{
				"internalType": "address",
				"name": "newOwner",
				"type": "address"
			}
		],
		"name": "transferOwnership",
		"outputs": [],
		"stateMutability": "nonpayable",
		"type": "function"
	}
]`
	const bintest = "60806040523480156200001157600080fd5b50336040518060400160405280600781526020017f4d79546f6b656e000000000000000000000000000000000000000000000000008152506040518060400160405280600381526020017f4d544b0000000000000000000000000000000000000000000000000000000000815250816003908162000090919062000846565b508060049081620000a2919062000846565b505050600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036200011a5760006040517f1e4fbdf700000000000000000000000000000000000000000000000000000000815260040162000111919062000972565b60405180910390fd5b6200012b816200014f60201b60201c565b5062000149336a084595161401484a0000006200021560201b60201c565b62000a64565b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905081600560006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b620002256200023b60201b60201c565b620002378282620002dd60201b60201c565b5050565b6200024b6200036a60201b60201c565b73ffffffffffffffffffffffffffffffffffffffff16620002716200037260201b60201c565b73ffffffffffffffffffffffffffffffffffffffff1614620002db576200029d6200036a60201b60201c565b6040517f118cdaa7000000000000000000000000000000000000000000000000000000008152600401620002d2919062000972565b60405180910390fd5b565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603620003525760006040517fec442f0500000000000000000000000000000000000000000000000000000000815260040162000349919062000972565b60405180910390fd5b62000366600083836200039c60201b60201c565b5050565b600033905090565b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603620003f2578060026000828254620003e59190620009be565b92505081905550620004c8565b60008060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff1681526020019081526020016000205490508181101562000481578381836040517fe450d38c000000000000000000000000000000000000000000000000000000008152600401620004789392919062000a0a565b60405180910390fd5b8181036000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160362000513578060026000828254039250508190555062000560565b806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055505b8173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051620005bf919062000a47565b60405180910390a3505050565b600081519050919050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052604160045260246000fd5b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806200064e57607f821691505b60208210810362000664576200066362000606565b5b50919050565b60008190508160005260206000209050919050565b60006020601f8301049050919050565b600082821b905092915050565b600060088302620006ce7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff826200068f565b620006da86836200068f565b95508019841693508086168417925050509392505050565b6000819050919050565b6000819050919050565b600062000727620007216200071b84620006f2565b620006fc565b620006f2565b9050919050565b6000819050919050565b620007438362000706565b6200075b62000752826200072e565b8484546200069c565b825550505050565b600090565b6200077262000763565b6200077f81848462000738565b505050565b5b81811015620007a7576200079b60008262000768565b60018101905062000785565b5050565b601f821115620007f657620007c0816200066a565b620007cb846200067f565b81016020851015620007db578190505b620007f3620007ea856200067f565b83018262000784565b50505b505050565b600082821c905092915050565b60006200081b60001984600802620007fb565b1980831691505092915050565b600062000836838362000808565b9150826002028217905092915050565b6200085182620005cc565b67ffffffffffffffff8111156200086d576200086c620005d7565b5b62000879825462000635565b62000886828285620007ab565b600060209050601f831160018114620008be5760008415620008a9578287015190505b620008b5858262000828565b86555062000925565b601f198416620008ce866200066a565b60005b82811015620008f857848901518255600182019150602085019450602081019050620008d1565b8683101562000918578489015162000914601f89168262000808565b8355505b6001600288020188555050505b505050505050565b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b60006200095a826200092d565b9050919050565b6200096c816200094d565b82525050565b600060208201905062000989600083018462000961565b92915050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b6000620009cb82620006f2565b9150620009d883620006f2565b9250828201905080821115620009f357620009f26200098f565b5b92915050565b62000a0481620006f2565b82525050565b600060608201905062000a21600083018662000961565b62000a306020830185620009f9565b62000a3f6040830184620009f9565b949350505050565b600060208201905062000a5e6000830184620009f9565b92915050565b6112dc8062000a746000396000f3fe608060405234801561001057600080fd5b50600436106100f55760003560e01c806370a082311161009757806395d89b411161006657806395d89b4114610260578063a9059cbb1461027e578063dd62ed3e146102ae578063f2fde38b146102de576100f5565b806370a08231146101ec578063715018a61461021c57806379cc6790146102265780638da5cb5b14610242576100f5565b806323b872dd116100d357806323b872dd14610166578063313ce5671461019657806340c10f19146101b457806342966c68146101d0576100f5565b806306fdde03146100fa578063095ea7b31461011857806318160ddd14610148575b600080fd5b6101026102fa565b60405161010f9190610f03565b60405180910390f35b610132600480360381019061012d9190610fbe565b61038c565b60405161013f9190611019565b60405180910390f35b6101506103af565b60405161015d9190611043565b60405180910390f35b610180600480360381019061017b919061105e565b6103b9565b60405161018d9190611019565b60405180910390f35b61019e6103e8565b6040516101ab91906110cd565b60405180910390f35b6101ce60048036038101906101c99190610fbe565b6103f1565b005b6101ea60048036038101906101e591906110e8565b610407565b005b61020660048036038101906102019190611115565b61041b565b6040516102139190611043565b60405180910390f35b610224610463565b005b610240600480360381019061023b9190610fbe565b610477565b005b61024a610497565b6040516102579190611151565b60405180910390f35b6102686104c1565b6040516102759190610f03565b60405180910390f35b61029860048036038101906102939190610fbe565b610553565b6040516102a59190611019565b60405180910390f35b6102c860048036038101906102c3919061116c565b610576565b6040516102d59190611043565b60405180910390f35b6102f860048036038101906102f39190611115565b6105fd565b005b606060038054610309906111db565b80601f0160208091040260200160405190810160405280929190818152602001828054610335906111db565b80156103825780601f1061035757610100808354040283529160200191610382565b820191906000526020600020905b81548152906001019060200180831161036557829003601f168201915b5050505050905090565b600080610397610683565b90506103a481858561068b565b600191505092915050565b6000600254905090565b6000806103c4610683565b90506103d185828561069d565b6103dc858585610732565b60019150509392505050565b60006012905090565b6103f9610826565b61040382826108ad565b5050565b610418610412610683565b8261092f565b50565b60008060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020549050919050565b61046b610826565b61047560006109b1565b565b61048982610483610683565b8361069d565b610493828261092f565b5050565b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905090565b6060600480546104d0906111db565b80601f01602080910402602001604051908101604052809291908181526020018280546104fc906111db565b80156105495780601f1061051e57610100808354040283529160200191610549565b820191906000526020600020905b81548152906001019060200180831161052c57829003601f168201915b5050505050905090565b60008061055e610683565b905061056b818585610732565b600191505092915050565b6000600160008473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008373ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905092915050565b610605610826565b600073ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff16036106775760006040517f1e4fbdf700000000000000000000000000000000000000000000000000000000815260040161066e9190611151565b60405180910390fd5b610680816109b1565b50565b600033905090565b6106988383836001610a77565b505050565b60006106a98484610576565b90507fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff81101561072c578181101561071c578281836040517ffb8f41b20000000000000000000000000000000000000000000000000000000081526004016107139392919061120c565b60405180910390fd5b61072b84848484036000610a77565b5b50505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff16036107a45760006040517f96c6fd1e00000000000000000000000000000000000000000000000000000000815260040161079b9190611151565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036108165760006040517fec442f0500000000000000000000000000000000000000000000000000000000815260040161080d9190611151565b60405180910390fd5b610821838383610c4e565b505050565b61082e610683565b73ffffffffffffffffffffffffffffffffffffffff1661084c610497565b73ffffffffffffffffffffffffffffffffffffffff16146108ab5761086f610683565b6040517f118cdaa70000000000000000000000000000000000000000000000000000000081526004016108a29190611151565b60405180910390fd5b565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff160361091f5760006040517fec442f050000000000000000000000000000000000000000000000000000000081526004016109169190611151565b60405180910390fd5b61092b60008383610c4e565b5050565b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff16036109a15760006040517f96c6fd1e0000000000000000000000000000000000000000000000000000000081526004016109989190611151565b60405180910390fd5b6109ad82600083610c4e565b5050565b6000600560009054906101000a900473ffffffffffffffffffffffffffffffffffffffff16905081600560006101000a81548173ffffffffffffffffffffffffffffffffffffffff021916908373ffffffffffffffffffffffffffffffffffffffff1602179055508173ffffffffffffffffffffffffffffffffffffffff168173ffffffffffffffffffffffffffffffffffffffff167f8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e060405160405180910390a35050565b600073ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff1603610ae95760006040517fe602df05000000000000000000000000000000000000000000000000000000008152600401610ae09190611151565b60405180910390fd5b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603610b5b5760006040517f94280d62000000000000000000000000000000000000000000000000000000008152600401610b529190611151565b60405180910390fd5b81600160008673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020819055508015610c48578273ffffffffffffffffffffffffffffffffffffffff168473ffffffffffffffffffffffffffffffffffffffff167f8c5be1e5ebec7d5bd14f71427d1e84f3dd0314c0f7b2291e5b200ac8c7c3b92584604051610c3f9190611043565b60405180910390a35b50505050565b600073ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff1603610ca0578060026000828254610c949190611272565b92505081905550610d73565b60008060008573ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002054905081811015610d2c578381836040517fe450d38c000000000000000000000000000000000000000000000000000000008152600401610d239392919061120c565b60405180910390fd5b8181036000808673ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff16815260200190815260200160002081905550505b600073ffffffffffffffffffffffffffffffffffffffff168273ffffffffffffffffffffffffffffffffffffffff1603610dbc5780600260008282540392505081905550610e09565b806000808473ffffffffffffffffffffffffffffffffffffffff1673ffffffffffffffffffffffffffffffffffffffff168152602001908152602001600020600082825401925050819055505b8173ffffffffffffffffffffffffffffffffffffffff168373ffffffffffffffffffffffffffffffffffffffff167fddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef83604051610e669190611043565b60405180910390a3505050565b600081519050919050565b600082825260208201905092915050565b60005b83811015610ead578082015181840152602081019050610e92565b60008484015250505050565b6000601f19601f8301169050919050565b6000610ed582610e73565b610edf8185610e7e565b9350610eef818560208601610e8f565b610ef881610eb9565b840191505092915050565b60006020820190508181036000830152610f1d8184610eca565b905092915050565b600080fd5b600073ffffffffffffffffffffffffffffffffffffffff82169050919050565b6000610f5582610f2a565b9050919050565b610f6581610f4a565b8114610f7057600080fd5b50565b600081359050610f8281610f5c565b92915050565b6000819050919050565b610f9b81610f88565b8114610fa657600080fd5b50565b600081359050610fb881610f92565b92915050565b60008060408385031215610fd557610fd4610f25565b5b6000610fe385828601610f73565b9250506020610ff485828601610fa9565b9150509250929050565b60008115159050919050565b61101381610ffe565b82525050565b600060208201905061102e600083018461100a565b92915050565b61103d81610f88565b82525050565b60006020820190506110586000830184611034565b92915050565b60008060006060848603121561107757611076610f25565b5b600061108586828701610f73565b935050602061109686828701610f73565b92505060406110a786828701610fa9565b9150509250925092565b600060ff82169050919050565b6110c7816110b1565b82525050565b60006020820190506110e260008301846110be565b92915050565b6000602082840312156110fe576110fd610f25565b5b600061110c84828501610fa9565b91505092915050565b60006020828403121561112b5761112a610f25565b5b600061113984828501610f73565b91505092915050565b61114b81610f4a565b82525050565b60006020820190506111666000830184611142565b92915050565b6000806040838503121561118357611182610f25565b5b600061119185828601610f73565b92505060206111a285828601610f73565b9150509250929050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052602260045260246000fd5b600060028204905060018216806111f357607f821691505b602082108103611206576112056111ac565b5b50919050565b60006060820190506112216000830186611142565b61122e6020830185611034565b61123b6040830184611034565b949350505050565b7f4e487b7100000000000000000000000000000000000000000000000000000000600052601160045260246000fd5b600061127d82610f88565b915061128883610f88565b92508282019050808211156112a05761129f611243565b5b9291505056fea2646970667358221220f2f8b50d7e9521daf5b02f0d3da5eb916b148d230631b7cce3fbba5be3f82e6764736f6c63430008140033"
	priKey, _ := gmsm.HexToSM2("39725efee3fb28614de3bacaffe4cc4bd8c436257e2c8bb887c4b5c4be45e76d")
	t.Log("公钥：", hex.EncodeToString(gmsm.CompressPubkey(&priKey.PublicKey)))
	testAddr := gmsm.PubkeyToAddress(priKey.PublicKey)
	t.Log("地址：", testAddr)
	sim := simTestBackend(testAddr)
	defer sim.Close()

	parsed, err := abi.JSON(strings.NewReader(abitest))
	if err != nil {
		t.Errorf("could not get code at test addr: %v", err)
	}
	contractAuth, err := bind.NewKeyedTransactorWithChainID(priKey, big.NewInt(0))
	addr, _, _, err := bind.DeployContract(contractAuth, parsed, common.FromHex(bintest), sim)
	if err != nil {
		t.Errorf("could not deploy contract: %v", err)
	}
	fmt.Println("deploy contract address: ", addr)
	fmt.Println("===========================================================================================================")

	//addr = common.HexToAddress("0x1cCc0D653B8674b24E1413c6795F1456cD4841a9")
	//no.2 step -> PendingCallContract
	res, err := callERC20(sim, ethereum.CallMsg{
		From:      testAddr,
		To:        &addr,
		Data:      common.Hex2Bytes("70a0823100000000000000000000000030e938b0630c02f394d17925fdb5fb046f70d452"),
		GasFeeCap: new(big.Int),
		GasTipCap: new(big.Int),
		Gas:       50000000,
		GasPrice:  new(big.Int),
		Value:     new(big.Int),
	})
	if err != nil {
		t.Errorf("could not call receive method on contract: %v", err)
	}
	fmt.Println(hex.EncodeToString(res))
}

func callERC20(b *SimulatedBackend, call ethereum.CallMsg) ([]byte, error) {
	block := b.pendingBlock
	stateDB := b.pendingState

	msg := callMsg{call}
	txContext := core.NewEVMTxContext(msg)
	evmContext := core.NewEVMBlockContext(block.Header(), b.blockchain, nil)

	vmEnv := vm.NewEVM(evmContext, txContext, stateDB, b.config, vm.Config{NoBaseFee: true})
	gasPool := new(core.GasPool).AddGas(math.MaxUint64)
	res, err := core.NewStateTransition(vmEnv, msg, gasPool).TransitionDb()
	return res.Return(), err
}
