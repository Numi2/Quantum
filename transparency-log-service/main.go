package main

import (
	"bufio"
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"flag"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

var (
	addr        = flag.String("addr", ":8085", "HTTP listen address")
	metricsAddr = flag.String("metrics-addr", ":9095", "Metrics listen address")
	storageFile = flag.String("storage-file", "transparency.log", "Path to append-only log storage")
	sthKeyFile  = flag.String("sth-key-file", "sth_key.pem", "Path to ECDSA P-256 private key for STH signing")
)

// LogEntry represents a certificate chain entry in the transparency log
type LogEntry struct {
	LeafInput string   `json:"leaf_input"`
	Chain     []string `json:"chain"`
	Timestamp int64    `json:"timestamp"`
}

func main() {
	flag.Parse()
	sthKey, err := loadOrCreateKey(*sthKeyFile)
	if err != nil {
		logger, _ := zap.NewProduction()
		sugar := logger.Sugar()
		sugar.Fatalf("failed to load STH key: %v", err)
	}

	logger, _ := zap.NewProduction()
	defer logger.Sync()
	sugar := logger.Sugar()

	// Start metrics server
	go func() {
		http.Handle("/metrics", promhttp.Handler())
		sugar.Infof("starting metrics server on %s", *metricsAddr)
		if err := http.ListenAndServe(*metricsAddr, nil); err != nil {
			sugar.Fatalf("metrics server failed: %v", err)
		}
	}()

	r := chi.NewRouter()
	r.Use(loggingMiddleware(sugar))
	r.Post("/ct/v1/add-chain", addChainHandler(sugar))
	r.Get("/ct/v1/get-sth", getSTHHandler(sugar, sthKey))
	r.Get("/ct/v1/get-entries", getEntriesHandler(sugar))
	r.Get("/ct/v1/get-proof-by-hash", getProofHandler(sugar))

	sugar.Infof("starting transparency log server on %s", *addr)
	if err := http.ListenAndServe(*addr, r); err != nil {
		sugar.Fatalf("server failed: %v", err)
	}
}

// loggingMiddleware logs requests as structured JSON
func loggingMiddleware(logger *zap.SugaredLogger) func(next http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			next.ServeHTTP(w, r)
			logger.Infow("request",
				"method", r.Method,
				"path", r.URL.Path,
				"duration", time.Since(start).String(),
				"remote", r.RemoteAddr,
			)
		})
	}
}

func addChainHandler(logger *zap.SugaredLogger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var entry LogEntry
		if err := json.NewDecoder(r.Body).Decode(&entry); err != nil {
			http.Error(w, "invalid payload", http.StatusBadRequest)
			logger.Warnf("invalid add-chain payload: %v", err)
			return
		}
		entry.Timestamp = time.Now().Unix()
		f, err := os.OpenFile(*storageFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			logger.Errorf("failed to open storage file: %v", err)
			return
		}
		defer f.Close()
		data, _ := json.Marshal(entry)
		f.Write(append(data, '\n'))
		w.WriteHeader(http.StatusAccepted)
	}
}

// Helpers for STH generation and Merkle tree
func loadOrCreateKey(path string) (*ecdsa.PrivateKey, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, err
		}
		der, err := x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, err
		}
		pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})
		if err := ioutil.WriteFile(path, pemBytes, 0600); err != nil {
			return nil, err
		}
		return key, nil
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	return x509.ParseECPrivateKey(block.Bytes)
}

func computeLeaves() ([][]byte, error) {
	data, err := ioutil.ReadFile(*storageFile)
	if err != nil {
		return nil, err
	}
	lines := bytes.Split(data, []byte{'\n'})
	var leaves [][]byte
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		leaves = append(leaves, line)
	}
	return leaves, nil
}

func getLeafHash(data []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0})
	h.Write(data)
	return h.Sum(nil)
}

func computeRoot(leaves [][]byte) []byte {
	var nodes [][]byte
	for _, leaf := range leaves {
		nodes = append(nodes, getLeafHash(leaf))
	}
	if len(nodes) == 0 {
		empty := sha256.Sum256(nil)
		return empty[:]
	}
	for len(nodes) > 1 {
		var next [][]byte
		for i := 0; i < len(nodes); i += 2 {
			left := nodes[i]
			var right []byte
			if i+1 < len(nodes) {
				right = nodes[i+1]
			} else {
				right = left
			}
			h := sha256.New()
			h.Write([]byte{1})
			h.Write(left)
			h.Write(right)
			next = append(next, h.Sum(nil))
		}
		nodes = next
	}
	return nodes[0]
}

// buildMerkleTree constructs all levels of the Merkle tree (leaf level first).
func buildMerkleTree(leafHashes [][]byte) [][][]byte {
	levels := [][][]byte{leafHashes}
	current := leafHashes
	for len(current) > 1 {
		var next [][]byte
		for i := 0; i < len(current); i += 2 {
			left := current[i]
			var right []byte
			if i+1 < len(current) {
				right = current[i+1]
			} else {
				right = left
			}
			h := sha256.New()
			h.Write([]byte{1})
			h.Write(left)
			h.Write(right)
			next = append(next, h.Sum(nil))
		}
		levels = append(levels, next)
		current = next
	}
	return levels
}

func serializeSTHInput(timestamp, treeSize uint64, rootHash []byte) []byte {
	buf := bytes.NewBuffer(nil)
	buf.WriteByte(0) // version v1
	buf.WriteByte(0) // signature type tree_hash
	binary.Write(buf, binary.BigEndian, timestamp)
	binary.Write(buf, binary.BigEndian, treeSize)
	buf.Write(rootHash)
	return buf.Bytes()
}

func getSTHHandler(logger *zap.SugaredLogger, sthKey *ecdsa.PrivateKey) http.HandlerFunc {
	type STH struct {
		TreeSize          uint64 `json:"tree_size"`
		Timestamp         uint64 `json:"timestamp"`
		Sha256RootHash    string `json:"sha256_root_hash"`
		TreeHeadSignature string `json:"tree_head_signature"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		leaves, err := computeLeaves()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			logger.Errorf("failed to read leaves: %v", err)
			return
		}
		treeSize := uint64(len(leaves))
		timestamp := uint64(time.Now().UnixNano() / int64(time.Millisecond))
		rootHash := computeRoot(leaves)
		input := serializeSTHInput(timestamp, treeSize, rootHash)
		hash := sha256.Sum256(input)
		sigBytes, err := ecdsa.SignASN1(rand.Reader, sthKey, hash[:])
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			logger.Errorf("failed to sign STH: %v", err)
			return
		}
		sth := STH{
			TreeSize:          treeSize,
			Timestamp:         timestamp,
			Sha256RootHash:    base64.StdEncoding.EncodeToString(rootHash),
			TreeHeadSignature: base64.StdEncoding.EncodeToString(sigBytes),
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(sth)
	}
}

func getEntriesHandler(logger *zap.SugaredLogger) http.HandlerFunc {
	type EntriesResponse struct {
		Entries []LogEntry `json:"entries"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		startStr := r.URL.Query().Get("start")
		endStr := r.URL.Query().Get("end")
		if startStr == "" || endStr == "" {
			http.Error(w, "missing start or end", http.StatusBadRequest)
			return
		}
		start, err1 := strconv.Atoi(startStr)
		end, err2 := strconv.Atoi(endStr)
		if err1 != nil || err2 != nil || start < 0 || end < start {
			http.Error(w, "invalid start or end", http.StatusBadRequest)
			return
		}
		file, err := os.Open(*storageFile)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			logger.Errorf("failed to open storage file: %v", err)
			return
		}
		defer file.Close()
		scanner := bufio.NewScanner(file)
		idx := 0
		var entries []LogEntry
		for scanner.Scan() {
			if idx >= start && idx < end {
				var entry LogEntry
				if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
					http.Error(w, "internal error", http.StatusInternalServerError)
					logger.Errorf("failed to parse entry: %v", err)
					return
				}
				entries = append(entries, entry)
			}
			if idx >= end {
				break
			}
			idx++
		}
		if err := scanner.Err(); err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			logger.Errorf("scanner error: %v", err)
			return
		}
		resp := EntriesResponse{Entries: entries}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}

func getProofHandler(logger *zap.SugaredLogger) http.HandlerFunc {
	type ProofResponse struct {
		LeafIndex int      `json:"leaf_index"`
		AuditPath []string `json:"audit_path"`
	}
	return func(w http.ResponseWriter, r *http.Request) {
		hashStr := r.URL.Query().Get("hash")
		treeSizeStr := r.URL.Query().Get("tree_size")
		if hashStr == "" || treeSizeStr == "" {
			http.Error(w, "missing hash or tree_size", http.StatusBadRequest)
			return
		}
		treeSize, err := strconv.Atoi(treeSizeStr)
		if err != nil || treeSize < 0 {
			http.Error(w, "invalid tree_size", http.StatusBadRequest)
			return
		}
		leaves, err := computeLeaves()
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			logger.Errorf("failed to read leaves: %v", err)
			return
		}
		if len(leaves) != treeSize {
			http.Error(w, "tree_size mismatch", http.StatusBadRequest)
			return
		}
		leafHash, err := base64.StdEncoding.DecodeString(hashStr)
		if err != nil {
			http.Error(w, "invalid hash", http.StatusBadRequest)
			return
		}
		// build leaf hashes
		var leafHashes [][]byte
		for _, leaf := range leaves {
			leafHashes = append(leafHashes, getLeafHash(leaf))
		}
		// find leaf index
		idx := -1
		for i, h := range leafHashes {
			if bytes.Equal(h, leafHash) {
				idx = i
				break
			}
		}
		if idx < 0 {
			http.Error(w, "leaf not found", http.StatusNotFound)
			return
		}
		// build tree levels
		levels := buildMerkleTree(leafHashes)
		// compute audit path
		var path [][]byte
		index := idx
		for level := 0; level < len(levels)-1; level++ {
			sibling := index ^ 1
			var siblingHash []byte
			if sibling < len(levels[level]) {
				siblingHash = levels[level][sibling]
			} else {
				siblingHash = levels[level][index]
			}
			path = append(path, siblingHash)
			index = index / 2
		}
		// encode path
		var auditPath []string
		for _, p := range path {
			auditPath = append(auditPath, base64.StdEncoding.EncodeToString(p))
		}
		resp := ProofResponse{LeafIndex: idx, AuditPath: auditPath}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}
}
