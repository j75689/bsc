// Copyright 2020 The go-ethereum Authors
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

// Tests that abnormal program termination (i.e.crash) and restart doesn't leave
// the database in some strange state with gaps in the chain, nor with block data
// dangling in the future.

package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus/ethash"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/ethdb/memorydb"
	"github.com/ethereum/go-ethereum/params"
)

func newMockVerifyPeer() *mockVerifyPeer {
	return &mockVerifyPeer{}
}

type requestRoot struct {
	blockNumber uint64
	blockHash   common.Hash
	diffHash    common.Hash
}

type mockVerifyPeer struct {
	callback func(*requestRoot)
}

func (peer *mockVerifyPeer) setCallBack(callback func(*requestRoot)) {
	peer.callback = callback
}

func (peer *mockVerifyPeer) RequestRoot(blockNumber uint64, blockHash common.Hash, diffHash common.Hash) error {
	if peer.callback != nil {
		peer.callback(&requestRoot{blockNumber, blockHash, diffHash})
	}
	return nil
}

func (peer *mockVerifyPeer) ID() string {
	return "mock_peer"
}

type mockVerifyPeers struct {
	peers []VerifyPeer
}

func (peers *mockVerifyPeers) GetVerifyPeers() []VerifyPeer {
	return peers.peers
}

func newMockRemoteVerifyPeer(peers []VerifyPeer) *mockVerifyPeers {
	return &mockVerifyPeers{peers}
}

func makeTestBackendWithRemoteValidator(blocks int) (*testBackend, error) {
	signer := types.HomesteadSigner{}
	// Create a database pre-initialize with a genesis block
	db := rawdb.NewMemoryDatabase()
	db.SetDiffStore(memorydb.New())
	(&Genesis{
		Config: params.TestChainConfig,
		Alloc:  GenesisAlloc{testAddr: {Balance: big.NewInt(100000000000000000)}},
	}).MustCommit(db)
	engine := ethash.NewFaker()

	peer := newMockVerifyPeer()
	peers := []VerifyPeer{peer}

	chain, err := NewBlockChain(db, nil, params.TestChainConfig, engine, vm.Config{},
		nil, nil, EnableBlockValidator(params.TestChainConfig, engine, FullVerify, newMockRemoteVerifyPeer(peers)))
	if err != nil {
		return nil, err
	}

	generator := func(i int, block *BlockGen) {
		// The chain maker doesn't have access to a chain, so the difficulty will be
		// lets unset (nil). Set it here to the correct value.
		block.SetCoinbase(testAddr)

		for idx, testBlock := range testBlocks {
			// Specific block setting, the index in this generator has 1 diff from specified blockNr.
			if i+1 == testBlock.blockNr {
				for _, testTransaction := range testBlock.txs {
					var transaction *types.Transaction
					if testTransaction.to == nil {
						transaction = types.NewContractCreation(block.TxNonce(testAddr),
							testTransaction.value, uint64(commonGas), testTransaction.gasPrice, testTransaction.data)
					} else {
						transaction = types.NewTransaction(block.TxNonce(testAddr), *testTransaction.to,
							testTransaction.value, uint64(commonGas), testTransaction.gasPrice, testTransaction.data)
					}
					tx, err := types.SignTx(transaction, signer, testKey)
					if err != nil {
						panic(err)
					}
					block.AddTxWithChain(chain, tx)
				}
				break
			}

			// Default block setting.
			if idx == len(testBlocks)-1 {
				// We want to simulate an empty middle block, having the same state as the
				// first one. The last is needs a state change again to force a reorg.
				for _, testTransaction := range testBlocks[0].txs {
					tx, err := types.SignTx(types.NewTransaction(block.TxNonce(testAddr), *testTransaction.to,
						testTransaction.value, uint64(commonGas), testTransaction.gasPrice, testTransaction.data), signer, testKey)
					if err != nil {
						panic(err)
					}
					block.AddTxWithChain(chain, tx)
				}
			}
		}
	}

	bs, _ := GenerateChain(params.TestChainConfig, chain.Genesis(), ethash.NewFaker(), db, blocks, generator)
	findBlock := func(hash common.Hash) *types.Block {
		for _, block := range bs {
			if block.Hash() == hash {
				return block
			}
		}
		return nil
	}

	peer.setCallBack(func(req *requestRoot) {
		if chain.validator != nil && chain.validator.RemoteVerifyManager() != nil {
			block := findBlock(req.blockHash)
			if block == nil {
				return
			}
			chain.validator.RemoteVerifyManager().HandleRootResponse(&VerifyResult{
				Status:      types.StatusFullVerified,
				BlockNumber: req.blockNumber,
				BlockHash:   req.blockHash,
				Root:        block.Root(),
			}, "mock")
		}
	})
	if _, err := chain.InsertChain(bs); err != nil {
		panic(err)
	}

	return &testBackend{
		db:    db,
		chain: chain,
	}, nil
}

func TestFastNode(t *testing.T) {
	_, err := makeTestBackendWithRemoteValidator(128)
	if err != nil {
		t.Fatalf(err.Error())
	}
}
