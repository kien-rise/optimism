package contracts

import (
	"context"
	"fmt"
	"math/big"
	"time"

	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/contracts/metrics"
	"github.com/ethereum-optimism/optimism/op-challenger/game/fault/types"
	gameTypes "github.com/ethereum-optimism/optimism/op-challenger/game/types"
	"github.com/ethereum-optimism/optimism/op-service/sources/batching"
	"github.com/ethereum-optimism/optimism/op-service/sources/batching/rpcblock"
	"github.com/ethereum/go-ethereum/common"
)

var (
	methodClaimData            = "claimData"
	methodMaxChallengeDuration = "maxChallengeDuration"
)

// OPSuccinctFaultDisputeGameContract wraps the OPSuccinctFaultDisputeGame contract (game type 42).
// This is a simpler dispute game that doesn't use the fault proof tree structure.
type OPSuccinctFaultDisputeGameContract struct {
	metrics     metrics.ContractMetricer
	multiCaller *batching.MultiCaller
	contract    *batching.BoundContract
}

// NewOPSuccinctFaultDisputeGame creates a new contract wrapper for OPSuccinctFaultDisputeGame.
func NewOPSuccinctFaultDisputeGame(
	m metrics.ContractMetricer,
	addr common.Address,
	caller *batching.MultiCaller,
) (*OPSuccinctFaultDisputeGameContract, error) {
	// Use a minimal ABI that covers the basic dispute game interface
	abi := mustParseAbi([]byte(`[
		{
			"inputs": [],
			"name": "l1Head",
			"outputs": [{"type": "bytes32"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "l2BlockNumber",
			"outputs": [{"type": "uint256"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "rootClaim",
			"outputs": [{"type": "bytes32"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "status",
			"outputs": [{"type": "uint8"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "maxChallengeDuration",
			"outputs": [{"type": "uint64"}],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [],
			"name": "claimData",
			"outputs": [
				{"type": "uint32", "name": "parentIndex"},
				{"type": "address", "name": "counteredBy"},
				{"type": "address", "name": "prover"},
				{"type": "bytes32", "name": "claim"},
				{"type": "uint8", "name": "status"},
				{"type": "uint64", "name": "deadline"}
			],
			"stateMutability": "view",
			"type": "function"
		},
		{
			"inputs": [{"type": "address"}],
			"name": "credit",
			"outputs": [{"type": "uint256"}],
			"stateMutability": "view",
			"type": "function"
		}
	]`))

	return &OPSuccinctFaultDisputeGameContract{
		metrics:     m,
		multiCaller: caller,
		contract:    batching.NewBoundContract(abi, addr),
	}, nil
}

// GetGameMetadata returns the basic game metadata.
func (g *OPSuccinctFaultDisputeGameContract) GetGameMetadata(ctx context.Context, block rpcblock.Block) (GameMetadata, error) {
	defer g.metrics.StartContractRequest("GetMetadata")()
	results, err := g.multiCaller.Call(ctx, block,
		g.contract.Call(methodL1Head),
		g.contract.Call(methodL2BlockNumber),
		g.contract.Call(methodRootClaim),
		g.contract.Call(methodStatus),
		g.contract.Call(methodMaxChallengeDuration),
	)
	if err != nil {
		return GameMetadata{}, fmt.Errorf("failed to retrieve game metadata: %w", err)
	}
	if len(results) != 5 {
		return GameMetadata{}, fmt.Errorf("expected 5 results but got %v", len(results))
	}
	l1Head := results[0].GetHash(0)
	l2BlockNumber := results[1].GetBigInt(0).Uint64()
	rootClaim := results[2].GetHash(0)
	status, err := gameTypes.GameStatusFromUint8(results[3].GetUint8(0))
	if err != nil {
		return GameMetadata{}, fmt.Errorf("failed to convert game status: %w", err)
	}
	maxClockDuration := results[4].GetUint64(0)

	return GameMetadata{
		L1Head:                  l1Head,
		L2SequenceNum:           l2BlockNumber,
		RootClaim:               rootClaim,
		Status:                  status,
		MaxClockDuration:        maxClockDuration,
		L2BlockNumberChallenged: false,
		L2BlockNumberChallenger: common.Address{},
	}, nil
}

// GetAllClaims returns a single root claim for this game type.
// OPSuccinctFaultDisputeGame doesn't use the claim tree structure.
func (g *OPSuccinctFaultDisputeGameContract) GetAllClaims(ctx context.Context, block rpcblock.Block) ([]types.Claim, error) {
	defer g.metrics.StartContractRequest("GetAllClaims")()

	// Get the root claim and claim data
	results, err := g.multiCaller.Call(ctx, block,
		g.contract.Call(methodRootClaim),
		g.contract.Call(methodClaimData),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load claims: %w", err)
	}
	if len(results) != 2 {
		return nil, fmt.Errorf("expected 2 results but got %v", len(results))
	}

	rootClaim := results[0].GetHash(0)
	claimDataResult := results[1]

	// Decode claimData struct
	// parentIndex := claimDataResult.GetUint32(0)
	counteredBy := claimDataResult.GetAddress(1)
	prover := claimDataResult.GetAddress(2)

	// Create a single root claim at position 0
	claimant := prover
	if claimant == (common.Address{}) {
		// If no prover, use counteredBy or zero address
		claimant = counteredBy
	}

	claims := []types.Claim{
		{
			ClaimData: types.ClaimData{
				Value:    rootClaim,
				Position: types.NewPositionFromGIndex(big.NewInt(1)), // Root position
				Bond:     big.NewInt(0),
			},
			CounteredBy:         counteredBy,
			Claimant:            claimant,
			Clock:               types.Clock{},
			ContractIndex:       0,
			ParentContractIndex: 0,
		},
	}

	return claims, nil
}

// GetCredits returns the credits for the given recipients.
func (g *OPSuccinctFaultDisputeGameContract) GetCredits(ctx context.Context, block rpcblock.Block, recipients ...common.Address) ([]*big.Int, error) {
	defer g.metrics.StartContractRequest("GetCredits")()
	calls := make([]batching.Call, 0, len(recipients))
	for _, recipient := range recipients {
		calls = append(calls, g.contract.Call(methodCredit, recipient))
	}
	results, err := g.multiCaller.Call(ctx, block, calls...)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve credits: %w", err)
	}
	credits := make([]*big.Int, 0, len(recipients))
	for _, result := range results {
		credits = append(credits, result.GetBigInt(0))
	}
	return credits, nil
}

// GetWithdrawals returns nil withdrawals for each recipient as this contract type doesn't use DelayedWETH.
func (g *OPSuccinctFaultDisputeGameContract) GetWithdrawals(ctx context.Context, block rpcblock.Block, recipients ...common.Address) ([]*WithdrawalRequest, error) {
	// OPSuccinctFaultDisputeGame doesn't use DelayedWETH withdrawals
	// Return nil for each recipient to satisfy the enricher's expectations
	withdrawals := make([]*WithdrawalRequest, len(recipients))
	return withdrawals, nil
}

// GetBalanceAndDelay returns zero balance and delay as this contract doesn't use DelayedWETH.
func (g *OPSuccinctFaultDisputeGameContract) GetBalanceAndDelay(ctx context.Context, block rpcblock.Block) (*big.Int, time.Duration, common.Address, error) {
	// This game type doesn't use DelayedWETH
	return big.NewInt(0), 0, common.Address{}, nil
}

// GetBondDistributionMode returns the bond distribution mode.
func (g *OPSuccinctFaultDisputeGameContract) GetBondDistributionMode(ctx context.Context, block rpcblock.Block) (types.BondDistributionMode, error) {
	// Return normal mode by default
	return types.NormalDistributionMode, nil
}

// IsResolved checks if claims are resolved. For OPSuccinctFaultDisputeGame, the single root claim
// is considered resolved when the game status is not IN_PROGRESS.
func (g *OPSuccinctFaultDisputeGameContract) IsResolved(ctx context.Context, block rpcblock.Block, claims ...types.Claim) ([]bool, error) {
	defer g.metrics.StartContractRequest("IsResolved")()

	// Get the game status
	result, err := g.multiCaller.SingleCall(ctx, block, g.contract.Call(methodStatus))
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve game status: %w", err)
	}

	status, err := gameTypes.GameStatusFromUint8(result.GetUint8(0))
	if err != nil {
		return nil, fmt.Errorf("failed to convert game status: %w", err)
	}

	// All claims have the same resolved status based on the game status
	isResolved := status != gameTypes.GameStatusInProgress
	resolved := make([]bool, len(claims))
	for i := range claims {
		resolved[i] = isResolved
	}

	return resolved, nil
}
