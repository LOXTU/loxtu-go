// Package db provides a thread-safe SurrealDB WebSocket connection pool.
package db

import (
	"context"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// DB is the global connection pool. Set once at startup, read-only after.
var DB *Pool

// Pool manages a fixed-size set of authenticated SurrealDB WebSocket connections.
// Thread-safe: concurrent callers borrow distinct connections. No global USE race.
// Auto-reconnect: dead connections (broken pipe, EOF) are replaced transparently.
//
// ── borrow/return pattern ──────────────────────────────────────────────────
//   conns is a buffered chan of *surrealdb.DB (capacity = maxConns).
//   borrow()  receives from the chan (blocks if all connections are busy).
//   returnConn() sends the connection back (unless the pool is closed, in
//   which case the connection is closed and discarded).
//   On Query error matching broken pipe / EOF / connection reset, the dead
//   connection is closed and a fresh one is created before returning to the
//   pool. The query is retried exactly once on the new connection.
type Pool struct {
	conns     chan *surrealdb.DB
	endpoint  string
	username  string
	password  string
	defaultNS string
	defaultDB string
	maxConns  int
	mu        sync.Mutex
	closed    bool
}

// NewPool creates maxConns authenticated SurrealDB connections.
// All connections are pre-authenticated and USE the default NS/DB.
func NewPool(ctx context.Context, endpoint, username, password, defaultNS, defaultDB string, maxConns int) (*Pool, error) {
	p := &Pool{
		conns:     make(chan *surrealdb.DB, maxConns),
		endpoint:  endpoint,
		username:  username,
		password:  password,
		defaultNS: defaultNS,
		defaultDB: defaultDB,
		maxConns:  maxConns,
	}
	for i := 0; i < maxConns; i++ {
		conn, err := p.newConn(ctx)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("pool init conn %d: %w", i, err)
		}
		p.conns <- conn
	}
	log.Printf("[dbpool] Initialised %d connections to %s (NS=%s DB=%s)", maxConns, endpoint, defaultNS, defaultDB)
	return p, nil
}

// newConn dials, authenticates, and selects the default namespace.
func (p *Pool) newConn(ctx context.Context) (*surrealdb.DB, error) {
	conn, err := surrealdb.New(p.endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if _, err := conn.SignIn(ctx, surrealdb.Auth{
		Username: p.username,
		Password: p.password,
	}); err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("signin: %w", err)
	}
	if err := conn.Use(ctx, p.defaultNS, p.defaultDB); err != nil {
		conn.Close(ctx)
		return nil, fmt.Errorf("use: %w", err)
	}
	return conn, nil
}

// borrow gets a connection from the pool. Blocks until one is available or ctx is cancelled.
func (p *Pool) borrow(ctx context.Context) (*surrealdb.DB, error) {
	select {
	case conn := <-p.conns:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// returnConn puts the connection back into the pool.
// If the pool is closed, the connection is closed and discarded.
func (p *Pool) returnConn(conn *surrealdb.DB) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		conn.Close(context.Background())
		return
	}
	p.conns <- conn
}

// reconnect replaces a dead connection with a fresh one.
func (p *Pool) reconnect(ctx context.Context, dead *surrealdb.DB) {
	dead.Close(context.Background())
	conn, err := p.newConn(ctx)
	if err != nil {
		log.Printf("[dbpool] reconnect failed: %v — discarding", err)
		return
	}
	p.conns <- conn
}

// connError reports whether err suggests the WebSocket connection is dead.
func connError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "i/o timeout")
}

// Query executes a SurrealQL query on a pooled connection.
//  1. Borrows a connection from the pool.
//  2. Calls USE $ns $dbName on that specific connection (no global race).
//  3. Executes the query with a 10-second timeout.
//  4. On connection-level error: replaces the dead conn, retries once.
//  5. Returns the connection to the pool.
func (p *Pool) Query(ctx context.Context, ns, dbName, sql string, vars map[string]any) ([]surrealdb.QueryResult[any], error) {
	conn, err := p.borrow(ctx)
	if err != nil {
		return nil, fmt.Errorf("borrow: %w", err)
	}

	if err := conn.Use(ctx, ns, dbName); err != nil {
		p.returnConn(conn)
		return nil, fmt.Errorf("use ns=%s db=%s: %w", ns, dbName, err)
	}

	c, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	results, err := surrealdb.Query[any](c, conn, sql, vars)
	if err != nil && connError(err) {
		// Dead connection — replace it, retry once
		log.Printf("[dbpool] Dead connection detected: %v — reconnecting", err)
		p.reconnect(c, conn)

		newConn, newErr := p.borrow(ctx)
		if newErr != nil {
			return nil, fmt.Errorf("borrow after reconnect: %w (original: %v)", newErr, err)
		}
		if err2 := newConn.Use(ctx, ns, dbName); err2 != nil {
			p.returnConn(newConn)
			return nil, fmt.Errorf("use after reconnect: %w (original: %v)", err2, err)
		}
		retry, retryErr := surrealdb.Query[any](c, newConn, sql, vars)
		if retryErr != nil {
			p.returnConn(newConn)
			return nil, fmt.Errorf("db query (retry failed): %w", retryErr)
		}
		p.returnConn(newConn)
		return *retry, nil
	}

	p.returnConn(conn)
	if err != nil {
		return nil, fmt.Errorf("db query: %w", err)
	}
	return *results, nil
}

// Close gracefully shuts down the pool: drains all connections and closes each.
func (p *Pool) Close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	p.mu.Unlock()

	for {
		select {
		case conn := <-p.conns:
			conn.Close(context.Background())
		default:
			close(p.conns)
			log.Printf("[dbpool] All %d pool connections closed", p.maxConns)
			return
		}
	}
}

// ── Env helpers ───────────────────────────────────────────────────────────

// GetRecordID converts a "table:id" string to a *models.RecordID pointer.
// The pointer's MarshalCBOR() produces a SurrealDB record CBOR tag,
// which is required for record<TYPE> fields (actor_id, etc.).
// Returns nil if id is empty or malformed.
func GetRecordID(idStr string) *models.RecordID {
	if idStr == "" || strings.Contains(idStr, "{") {
		return nil
	}
	parts := strings.SplitN(idStr, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return nil
	}
	r := models.NewRecordID(parts[0], parts[1])
	return &r
}

// PoolFromEnv creates a Pool from environment variables with sensible defaults.
func PoolFromEnv() (*Pool, error) {
	endpoint := envOr("SURREALDB_ENDPOINT", "ws://surrealdb:8881/rpc")
	user := envOr("SURREALDB_USER", "root")
	pass := envOr("SURREALDB_PASS", "root")
	ns := envOr("SURREALDB_NS", "loxtu")
	dbName := envOr("SURREALDB_DB", "loxtu")
	maxConns := envInt("SURREALDB_POOL_SIZE", 10)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	return NewPool(ctx, endpoint, user, pass, ns, dbName, maxConns)
}

func envOr(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		var n int
		if _, err := fmt.Sscanf(v, "%d", &n); err == nil {
			return n
		}
	}
	return fallback
}