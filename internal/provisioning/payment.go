package provisioning

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/big"
	"net/http"
	"strings"
	"sync"
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

// Minimum value thresholds in native token (conservative floor).
// These are hardcoded minimums as a safety net against dust payments.
// The CoinGecko price oracle provides dynamic USD verification on top of these.
var chainMinWei = map[string]*big.Int{
	ChainETH:  big.NewInt(3e15),  // ~0.003 ETH (~$7-8 buffer at typical prices)
	ChainBase: big.NewInt(3e15),  // same as ETH (Base uses ETH)
	ChainBSC:  big.NewInt(15e15), // ~0.015 BNB
}

// Public RPC endpoints for tx verification.
var chainRPCs = map[string]string{
	ChainETH:  "https://eth.llamarpc.com",
	ChainBase: "https://mainnet.base.org",
	ChainBSC:  "https://bsc-dataseed1.binance.org",
}

// CoinGecko IDs for native tokens by chain.
var chainCoinGeckoID = map[string]string{
	ChainETH:    "ethereum",
	ChainBase:   "ethereum", // Base uses ETH as native token
	ChainBSC:    "binancecoin",
	ChainSolana: "solana",
}

// priceCache stores recently fetched USD prices to avoid hitting CoinGecko rate limits.
type priceCache struct {
	mu        sync.RWMutex
	prices    map[string]float64
	fetchedAt time.Time
}

const priceCacheTTL = 5 * time.Minute

// PaymentVerifier checks on-chain transactions to confirm payments.
type PaymentVerifier struct {
	db      *storage.DB
	cfg     *config.Config
	logger  *slog.Logger
	client  *http.Client
	cache   priceCache
}

// NewPaymentVerifier creates a new verifier.
func NewPaymentVerifier(db *storage.DB, cfg *config.Config, logger *slog.Logger) *PaymentVerifier {
	return &PaymentVerifier{
		db:     db,
		cfg:    cfg,
		logger: logger,
		client: &http.Client{Timeout: 15 * time.Second},
		cache: priceCache{
			prices: make(map[string]float64),
		},
	}
}

// VerifyTransaction checks if a transaction on the given chain sent funds to our wallet.
// Returns the actual USD value of the payment and nil error if valid.
func (v *PaymentVerifier) VerifyTransaction(txHash, chain string) (float64, error) {
	switch chain {
	case ChainETH, ChainBase, ChainBSC:
		return v.verifyEVM(txHash, chain)
	case ChainSolana:
		return v.verifySolana(txHash)
	default:
		return 0, fmt.Errorf("unsupported chain: %s", chain)
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
		usdValue, err := v.VerifyTransaction(p.TxHash, chain)
		if err != nil {
			// Check if payment is older than 24h — mark as failed
			if time.Since(p.CreatedAt) > 24*time.Hour {
				v.logger.Warn("payment expired", "tx", p.TxHash, "error", err)
				v.db.UpdatePaymentStatus(p.ID, storage.PaymentFailed, nil)
			}
			continue
		}

		now := time.Now()
		p.AmountUSD = usdValue
		v.db.UpdatePaymentStatus(p.ID, storage.PaymentConfirmed, &now)
		v.logger.Info("payment confirmed", "tx", p.TxHash, "chain", chain, "usd_value", usdValue)
	}
}

// --- CoinGecko Price Oracle ---

// fetchPrice returns the current USD price for the native token of the given chain.
// Prices are cached for 5 minutes to avoid hitting CoinGecko rate limits.
func (v *PaymentVerifier) fetchPrice(chain string) (float64, error) {
	coinID, ok := chainCoinGeckoID[chain]
	if !ok {
		return 0, fmt.Errorf("no CoinGecko ID for chain %s", chain)
	}

	// Check cache (read lock)
	v.cache.mu.RLock()
	if time.Since(v.cache.fetchedAt) < priceCacheTTL {
		if price, ok := v.cache.prices[coinID]; ok {
			v.cache.mu.RUnlock()
			return price, nil
		}
	}
	v.cache.mu.RUnlock()

	// Cache miss or expired — fetch from CoinGecko
	url := fmt.Sprintf("https://api.coingecko.com/api/v3/simple/price?ids=%s&vs_currencies=usd", coinID)
	resp, err := v.client.Get(url)
	if err != nil {
		return 0, fmt.Errorf("coingecko request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return 0, fmt.Errorf("coingecko returned status %d", resp.StatusCode)
	}

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return 0, fmt.Errorf("reading coingecko response: %w", err)
	}

	// Response format: {"ethereum":{"usd":3456.78}}
	var parsed map[string]map[string]float64
	if err := json.Unmarshal(data, &parsed); err != nil {
		return 0, fmt.Errorf("parsing coingecko response: %w", err)
	}

	coinData, ok := parsed[coinID]
	if !ok {
		return 0, fmt.Errorf("coingecko response missing data for %s", coinID)
	}
	price, ok := coinData["usd"]
	if !ok || price <= 0 {
		return 0, fmt.Errorf("coingecko returned invalid USD price for %s", coinID)
	}

	// Update cache (write lock)
	v.cache.mu.Lock()
	v.cache.prices[coinID] = price
	v.cache.fetchedAt = time.Now()
	v.cache.mu.Unlock()

	v.logger.Debug("fetched price from CoinGecko", "coin", coinID, "usd", price)
	return price, nil
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

func (v *PaymentVerifier) verifyEVM(txHash, chain string) (float64, error) {
	rpc, ok := chainRPCs[chain]
	if !ok {
		return 0, fmt.Errorf("no RPC for chain %s", chain)
	}

	wallet := strings.ToLower(v.WalletForChain(chain))
	if wallet == "" {
		return 0, fmt.Errorf("no wallet configured for %s", chain)
	}

	// 1. Get transaction details
	tx, err := v.evmCall(rpc, "eth_getTransactionByHash", []interface{}{txHash})
	if err != nil {
		return 0, fmt.Errorf("rpc error: %w", err)
	}
	if tx.Result == nil {
		return 0, fmt.Errorf("transaction not found on %s", chain)
	}

	// 2. Verify recipient is our wallet
	if strings.ToLower(tx.Result.To) != wallet {
		return 0, fmt.Errorf("transaction recipient %s does not match wallet %s", tx.Result.To, wallet)
	}

	// 3. Verify value is non-trivial (static sanity check)
	value := new(big.Int)
	if strings.HasPrefix(tx.Result.Value, "0x") {
		value.SetString(tx.Result.Value[2:], 16)
	}
	if minWei, ok := chainMinWei[chain]; ok {
		if value.Cmp(minWei) < 0 {
			return 0, fmt.Errorf("transaction value too low: %s wei", value.String())
		}
	}

	// 4. Convert wei to token amount and verify USD value via price oracle
	weiFloat := new(big.Float).SetInt(value)
	tokenAmount, _ := new(big.Float).Quo(weiFloat, big.NewFloat(1e18)).Float64()

	priceUSD, err := v.fetchPrice(chain)
	if err != nil {
		v.logger.Warn("price oracle unavailable, falling back to static check", "chain", chain, "error", err)
		// Fall through — static minimum already passed above
	} else {
		usdValue := tokenAmount * priceUSD
		requiredUSD := v.cfg.Provisioning.PriceUSD * 0.85 // 15% slippage tolerance
		if usdValue < requiredUSD {
			return 0, fmt.Errorf("payment USD value $%.2f is below minimum $%.2f (%.4f token @ $%.2f)",
				usdValue, requiredUSD, tokenAmount, priceUSD)
		}
	}

	// 5. Verify transaction was successful (check receipt)
	receipt, err := v.evmReceiptCall(rpc, txHash)
	if err != nil {
		return 0, fmt.Errorf("receipt error: %w", err)
	}
	if receipt.Result == nil {
		return 0, fmt.Errorf("transaction receipt not found (may be pending)")
	}
	if receipt.Result.Status != "0x1" {
		return 0, fmt.Errorf("transaction reverted")
	}

	// Calculate actual USD value for the payment record
	actualUSD := tokenAmount * priceUSD
	if priceUSD == 0 {
		// Price oracle was unavailable; use configured price as fallback
		actualUSD = v.cfg.Provisioning.PriceUSD
	}

	return math.Round(actualUSD*100) / 100, nil
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

func (v *PaymentVerifier) verifySolana(txHash string) (float64, error) {
	wallet := v.WalletForChain(ChainSolana)
	if wallet == "" {
		return 0, fmt.Errorf("no Solana wallet configured")
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
		return 0, fmt.Errorf("solana rpc error: %w", err)
	}
	defer resp.Body.Close()

	data, _ := io.ReadAll(resp.Body)
	var result solanaTxResult
	if err := json.Unmarshal(data, &result); err != nil {
		return 0, fmt.Errorf("parsing solana response: %w", err)
	}
	if result.Error != nil {
		return 0, fmt.Errorf("solana rpc error: %s", result.Error.Message)
	}
	if result.Result == nil {
		return 0, fmt.Errorf("transaction not found on Solana")
	}
	if result.Result.Meta == nil || result.Result.Meta.Err != nil {
		return 0, fmt.Errorf("transaction failed on Solana")
	}

	// Find our wallet in the account keys and check it received funds
	accounts := result.Result.Transaction.Message.AccountKeys
	preBalances := result.Result.Meta.PreBalances
	postBalances := result.Result.Meta.PostBalances

	for i, acct := range accounts {
		if acct == wallet {
			if i < len(preBalances) && i < len(postBalances) {
				received := postBalances[i] - preBalances[i]
				// Static minimum ~0.05 SOL (50M lamports) as sanity check
				if received <= 50_000_000 {
					return 0, fmt.Errorf("wallet received %d lamports, too low", received)
				}

				// Convert lamports to SOL and verify USD value via price oracle
				solAmount := float64(received) / 1e9

				priceUSD, err := v.fetchPrice(ChainSolana)
				if err != nil {
					v.logger.Warn("price oracle unavailable for SOL, falling back to static check", "error", err)
					// Static minimum already passed; use configured price as fallback
					return v.cfg.Provisioning.PriceUSD, nil
				}

				usdValue := solAmount * priceUSD
				requiredUSD := v.cfg.Provisioning.PriceUSD * 0.85 // 15% slippage tolerance
				if usdValue < requiredUSD {
					return 0, fmt.Errorf("payment USD value $%.2f is below minimum $%.2f (%.6f SOL @ $%.2f)",
						usdValue, requiredUSD, solAmount, priceUSD)
				}

				return math.Round(usdValue*100) / 100, nil
			}
		}
	}

	return 0, fmt.Errorf("wallet %s not found in transaction accounts", wallet)
}
