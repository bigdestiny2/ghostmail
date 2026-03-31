package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/ghostmail/ghostmail/internal/config"
	"github.com/ghostmail/ghostmail/internal/storage"
)

// Supported chains for payment.
const (
	ChainETH    = "eth"
	ChainBase   = "base"
	ChainBSC    = "bsc"
	ChainSolana = "solana"
)

// Minimum value thresholds in native token (approximate $10 worth).
// These are conservative minimums; actual price checking uses the API response value.
var chainMinWei = map[string]*big.Int{
	ChainETH:  big.NewInt(1e15),  // ~0.001 ETH minimum (sanity check)
	ChainBase: big.NewInt(1e15),  // same
	ChainBSC:  big.NewInt(1e16),  // ~0.01 BNB minimum
}

// Public RPC endpoints for tx verification.
var chainRPCs = map[string]string{
	ChainETH:  "https://eth.llamarpc.com",
	ChainBase: "https://mainnet.base.org",
	ChainBSC:  "https://bsc-dataseed1.binance.org",
}

// PaymentVerifier checks on-chain transactions to confirm payments.
type PaymentVerifier struct {
	db      *storage.DB
	cfg     *config.Config
	logger  *slog.Logger
	client  *http.Client
}

// NewPaymentVerifier creates a new verifier.
func NewPaymentVerifier(db *storage.DB, cfg *config.Config, logger *slog.Logger) *PaymentVerifier {
	return &PaymentVerifier{
		db:     db,
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 15 * time.Second},
	}
}

// VerifyTransaction checks if a transaction on the given chain sent funds to our wallet.
// Returns nil if the payment is valid.
func (v *PaymentVerifier) VerifyTransaction(txHash, chain string) error {
	switch chain {
	case ChainETH, ChainBase, ChainBSC:
		return v.verifyEVM(txHash, chain)
	case ChainSolana:
		return v.verifySolana(txHash)
	default:
		return fmt.Errorf("unsupported chain: %s", chain)
	}
}

// WalletForChain returns the configured wallet address for a chain.
func (v *PaymentVerifier) WalletForChain(chain string) string {
	switch chain {
	case ChainETH, ChainBase, ChainBSC:
		if v.cfg.Provisioning.Wallets.EVM != "" {
			return v.cfg.Provisioning.Wallets.EVM
		}
		return v.cfg.Provisioning.CryptoPaymentAddr
	case ChainSolana:
		return v.cfg.Provisioning.Wallets.Solana
	default:
		return ""
	}
}

// SupportedChains returns chains that have a wallet configured.
func (v *PaymentVerifier) SupportedChains() []string {
	var chains []string
	evmAddr := v.cfg.Provisioning.Wallets.EVM
	if evmAddr == "" {
		evmAddr = v.cfg.Provisioning.CryptoPaymentAddr
	}
	if evmAddr != "" {
		chains = append(chains, ChainETH, ChainBase, ChainBSC)
	}
	if v.cfg.Provisioning.Wallets.Solana != "" {
		chains = append(chains, ChainSolana)
	}
	return chains
}

// RunVerifier periodically checks pending payments for on-chain confirmation.
func (v *PaymentVerifier) RunVerifier(ctx context.Context) {
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			v.checkPending()
		}
	}
}

func (v *PaymentVerifier) checkPending() {
	payments, err := v.db.ListPendingPayments()
	if err != nil {
		v.logger.Error("payment verifier: list pending error", "error", err)
		return
	}

	for _, p := range payments {
		chain := p.CryptoCurrency
		if err := v.VerifyTransaction(p.TxHash, chain); err != nil {
			// Check if payment is older than 24h — mark as failed
			if time.Since(p.CreatedAt) > 24*time.Hour {
				v.logger.Warn("payment expired", "tx", p.TxHash, "error", err)
				v.db.UpdatePaymentStatus(p.ID, storage.PaymentFailed, nil)
			}
			continue
		}

		now := time.Now()
		v.db.UpdatePaymentStatus(p.ID, storage.PaymentConfirmed, &now)
		v.logger.Info("payment confirmed", "tx", p.TxHash, "chain", chain)
	}
}

// --- EVM Verification (ETH, Base, BSC) ---

type jsonRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type evmTxResult struct {
	JSONRPC string `json:"jsonrpc"`
	Result  *struct {
		From  string `json:"from"`
		To    string `json:"to"`
		Value string `json:"value"` // hex wei
		Hash  string `json:"hash"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

type evmReceiptResult struct {
	JSONRPC string `json:"jsonrpc"`
	Result  *struct {
		Status string `json:"status"` // "0x1" = success
	} `json:"result"`
}

func (v *PaymentVerifier) verifyEVM(txHash, chain string) error {
	rpc, ok := chainRPCs[chain]
	if !ok {
		return fmt.Errorf("no RPC for chain %s", chain)
	}

	wallet := strings.ToLower(v.WalletForChain(chain))
	if wallet == "" {
		return fmt.Errorf("no wallet configured for %s", chain)
	}

	// 1. Get transaction details
	tx, err := v.evmCall(rpc, "eth_getTransactionByHash", []interface{}{txHash})
	if err != nil {
		return fmt.Errorf("rpc error: %w", err)
	}
	if tx.Result == nil {
		return fmt.Errorf("transaction not found on %s", chain)
	}

	// 2. Verify recipient is our wallet
	if strings.ToLower(tx.Result.To) != wallet {
		return fmt.Errorf("transaction recipient %s does not match wallet %s", tx.Result.To, wallet)
	}

	// 3. Verify value is non-trivial (sanity check)
	value := new(big.Int)
	if strings.HasPrefix(tx.Result.Value, "0x") {
		value.SetString(tx.Result.Value[2:], 16)
	}
	if minWei, ok := chainMinWei[chain]; ok {
		if value.Cmp(minWei) < 0 {
			return fmt.Errorf("transaction value too low: %s wei", value.String())
		}
	}

	// 4. Verify transaction was successful (check receipt)
	receipt, err := v.evmReceiptCall(rpc, txHash)
	if err != nil {
		return fmt.Errorf("receipt error: %w", err)
	}
	if receipt.Result == nil {
		return fmt.Errorf("transaction receipt not found (may be pending)")
	}
	if receipt.Result.Status != "0x1" {
		return fmt.Errorf("transaction reverted")
	}

	return nil
}

func (v *PaymentVerifier) evmCall(rpc, method string, params []interface{}) (*evmTxResult, error) {
	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  method,
		Params:  params,
		ID:      1,
	}
	body, _ := json.Marshal(reqBody)

	resp, err := v.client.Post(rpc, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result evmTxResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	if result.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", result.Error.Message)
	}
	return &result, nil
}

func (v *PaymentVerifier) evmReceiptCall(rpc, txHash string) (*evmReceiptResult, error) {
	reqBody := jsonRPCRequest{
		JSONRPC: "2.0",
		Method:  "eth_getTransactionReceipt",
		Params:  []interface{}{txHash},
		ID:      1,
	}
	body, _ := json.Marshal(reqBody)

	resp, err := v.client.Post(rpc, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result evmReceiptResult
	if err := json.Unmarshal(data, &result); err != nil {
		return nil, fmt.Errorf("parsing response: %w", err)
	}
	return &result, nil
}

// --- Solana Verification ---

type solanaRPCRequest struct {
	JSONRPC string        `json:"jsonrpc"`
	Method  string        `json:"method"`
	Params  []interface{} `json:"params"`
	ID      int           `json:"id"`
}

type solanaTxResult struct {
	Result *struct {
		Meta *struct {
			Err               interface{}   `json:"err"`
			PreBalances       []int64       `json:"preBalances"`
			PostBalances      []int64       `json:"postBalances"`
		} `json:"meta"`
		Transaction *struct {
			Message struct {
				AccountKeys []string `json:"accountKeys"`
			} `json:"message"`
		} `json:"transaction"`
	} `json:"result"`
	Error *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (v *PaymentVerifier) verifySolana(txHash string) error {
	wallet := v.WalletForChain(ChainSolana)
	if wallet == "" {
		return fmt.Errorf("no Solana wallet configured")
	}

	rpc := "https://api.mainnet-beta.solana.com"

	reqBody := solanaRPCRequest{
		JSONRPC: "2.0",
		Method:  "getTransaction",
		Params: []interface{}{
			txHash,
			map[string]interface{}{
				"encoding":                       "json",
				"maxSupportedTransactionVersion": 0,
			},
		},
		ID: 1,
	}
	body, _ := json.Marshal(reqBody)

	resp, err := v.client.Post(rpc, "application/json", strings.NewReader(string(body)))
	if err != nil {
		return fmt.Errorf("solana rpc error: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result solanaTxResult
	if err := json.Unmarshal(data, &result); err != nil {
		return fmt.Errorf("parsing solana response: %w", err)
	}
	if result.Error != nil {
		return fmt.Errorf("solana rpc error: %s", result.Error.Message)
	}
	if result.Result == nil {
		return fmt.Errorf("transaction not found on Solana")
	}
	if result.Result.Meta == nil || result.Result.Meta.Err != nil {
		return fmt.Errorf("transaction failed on Solana")
	}

	// Find our wallet in the account keys and check it received funds
	accounts := result.Result.Transaction.Message.AccountKeys
	preBalances := result.Result.Meta.PreBalances
	postBalances := result.Result.Meta.PostBalances

	for i, acct := range accounts {
		if acct == wallet {
			if i < len(preBalances) && i < len(postBalances) {
				received := postBalances[i] - preBalances[i]
				// Minimum ~0.01 SOL (10M lamports) as sanity check
				if received > 10_000_000 {
					return nil // Payment verified
				}
				return fmt.Errorf("wallet received %d lamports, too low", received)
			}
		}
	}

	return fmt.Errorf("wallet %s not found in transaction accounts", wallet)
}
