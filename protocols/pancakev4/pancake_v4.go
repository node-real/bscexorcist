// Package pancakev4 provides swap event parsing for PancakeSwap v4 pools.
package pancakev4

import (
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"

	"github.com/48Club/bscexorcist/protocols/tools"
)

// Swap implements protocols.SwapEvent for PancakeSwap v4 pools.
//
// PCS v4 emits Swap(PoolId indexed id, address indexed sender, int128 amount0, int128 amount1, ...)
// for both CLPool and BinPool. We only need PoolId + amounts for sandwich detection.
type Swap struct {
	poolID  [32]byte
	amount0 *big.Int
	amount1 *big.Int
}

// PairID returns a pseudo-address derived from the first 20 bytes of PoolId.
func (s *Swap) PairID() common.Address {
	return common.BytesToAddress(s.poolID[:20])
}

// IsToken0To1 returns true if the swap direction is token0 -> token1.
//
// Convention (consistent with existing v4-style parsing):
// amount0 > 0 means token0 enters the pool (sell token0, buy token1).
func (s *Swap) IsToken0To1() bool {
	return s.amount0.Sign() > 0
}

// AmountIn returns the input amount for the swap.
func (s *Swap) AmountIn() *big.Int {
	if s.amount0.Sign() > 0 {
		return new(big.Int).Set(s.amount0)
	}
	return new(big.Int).Neg(s.amount1)
}

// AmountOut returns the output amount for the swap.
func (s *Swap) AmountOut() *big.Int {
	if s.amount0.Sign() < 0 {
		return new(big.Int).Neg(s.amount0)
	}
	return new(big.Int).Set(s.amount1)
}

// ParseCLPoolSwap parses a PancakeSwap v4 CLPool swap log into a Swap struct.
// Returns nil if the log is not a valid CLPool swap event payload.
func ParseCLPoolSwap(log *types.Log) *Swap {
	return parseSwap(log)
}

// ParseBinPoolSwap parses a PancakeSwap v4 BinPool swap log into a Swap struct.
// Returns nil if the log is not a valid BinPool swap event payload.
func ParseBinPoolSwap(log *types.Log) *Swap {
	return parseSwap(log)
}

func parseSwap(log *types.Log) *Swap {
	// Topics:
	// - Topics[0] = signature
	// - Topics[1] = PoolId (bytes32)
	// - Topics[2] = sender (address)
	if len(log.Topics) != 3 || len(log.Data) < 64 {
		return nil
	}

	var poolID [32]byte
	copy(poolID[:], log.Topics[1].Bytes())

	amount0 := tools.DecodeSignedInt256(log.Data[:32])
	amount1 := tools.DecodeSignedInt256(log.Data[32:64])

	return &Swap{
		poolID:  poolID,
		amount0: amount0,
		amount1: amount1,
	}
}
