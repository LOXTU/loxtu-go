// Package surrealdb implements core identity/audit store ports against SurrealDB.
// No package-level DB global. No ENV reads in construction (pass Config from main).
// DTOs for row mapping are unexported; public APIs return domain types only.
package surrealdb

import (
	"context"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	driver "github.com/surrealdb/surrealdb.go"
	"github.com/surrealdb/surrealdb.go/pkg/models"
)

// Config is injected by the composition root (main). Adapter never reads ENV.
type Config struct {
	Endpoint  string
	Username  string
	Password  string
	Namespace string
	Database  string
	MaxConns  int
}

// Pool is a thread-safe SurrealDB WebSocket connection pool.
type Pool struct {
	conns     chan *driver.DB
	endpoint  string
	username  string
	password  string
	defaultNS string
	defaultDB string
	maxConns  int
	mu        sync.Mutex
	closed    bool
}

// NewPool creates maxConns authenticated connections from cfg.
// ctx bounds dial/auth during bootstrap.
func NewPool(ctx context.Context, cfg Config) (*Pool, error) {
	if cfg.MaxConns <= 0 {
		cfg.MaxConns = 10
	}
	if cfg.Endpoint == "" {
		return nil, fmt.Errorf("surrealdb: empty Endpoint")
	}
	p := &Pool{
		conns:     make(chan *driver.DB, cfg.MaxConns),
		endpoint:  cfg.Endpoint,
		username:  cfg.Username,
		password:  cfg.Password,
		defaultNS: cfg.Namespace,
		defaultDB: cfg.Database,
		maxConns:  cfg.MaxConns,
	}
	for i := 0; i < cfg.MaxConns; i++ {
		conn, err := p.newConn(ctx)
		if err != nil {
			p.Close()
			return nil, fmt.Errorf("pool init conn %d: %w", i, err)
		}
		p.conns <- conn
	}
	log.Printf("[dbpool] Initialised %d connections to %s (NS=%s DB=%s)", cfg.MaxConns, cfg.Endpoint, cfg.Namespace, cfg.Database)
	return p, nil
}

func (p *Pool) newConn(ctx context.Context) (*driver.DB, error) {
	conn, err := driver.New(p.endpoint)
	if err != nil {
		return nil, fmt.Errorf("dial: %w", err)
	}
	if _, err := conn.SignIn(ctx, driver.Auth{
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

func (p *Pool) borrow(ctx context.Context) (*driver.DB, error) {
	select {
	case conn := <-p.conns:
		return conn, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (p *Pool) returnConn(conn *driver.DB) {
	p.mu.Lock()
	closed := p.closed
	p.mu.Unlock()
	if closed {
		conn.Close(context.Background())
		return
	}
	p.conns <- conn
}

func (p *Pool) reconnect(ctx context.Context, dead *driver.DB) {
	dead.Close(context.Background())
	conn, err := p.newConn(ctx)
	if err != nil {
		log.Printf("[dbpool] reconnect failed: %v — discarding", err)
		return
	}
	p.conns <- conn
}

func connError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "broken pipe") ||
		strings.Contains(s, "connection reset") ||
		strings.Contains(s, "EOF") ||
		strings.Contains(s, "use of closed network connection") ||
		strings.Contains(s, "i/o timeout")
}

// Query executes SurrealQL on ns/dbName.
func (p *Pool) Query(ctx context.Context, ns, dbName, sql string, vars map[string]any) ([]driver.QueryResult[any], error) {
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

	results, err := driver.Query[any](c, conn, sql, vars)
	if err != nil && connError(err) {
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
		retry, retryErr := driver.Query[any](c, newConn, sql, vars)
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

// CreateRecord uses the SDK's "create" RPC method (different from "query").
// May handle CBOR bytes differently — use for tables where Query fails with Parse error.
func (p *Pool) CreateRecord(ctx context.Context, ns, dbName, table string, data map[string]any) (map[string]any, error) {
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

	result, err := driver.Create[map[string]any](c, conn, models.Table(table), data)
	if err != nil {
		if connError(err) {
			p.reconnect(c, conn)
			return nil, fmt.Errorf("create record: %w", err)
		}
		p.returnConn(conn)
		return nil, fmt.Errorf("create record: %w", err)
	}

	p.returnConn(conn)
	return *result, nil
}

// Close drains and closes all connections.
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

// getRecordID converts "table:id" to *models.RecordID for record<TYPE> fields.
// Unexported: Surreal-specific CBOR helper must not leave this adapter package.
func getRecordID(idStr string) *models.RecordID {
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

// formatRecordID normalises SurrealDB record id values to "table:id".
// Unexported: parsing quirk of the Surreal SDK, not a domain concept.
func formatRecordID(id any) string {
	if id == nil {
		return ""
	}
	if s, ok := id.(string); ok {
		return s
	}
	if s, ok := id.(fmt.Stringer); ok {
		return s.String()
	}
	if m, ok := id.(map[string]any); ok {
		tb, _ := m["tb"].(string)
		if tb == "" {
			tb, _ = m["Table"].(string)
		}
		idVal := m["id"]
		if idVal == nil {
			idVal = m["ID"]
		}
		if tb != "" && idVal != nil {
			return fmt.Sprintf("%s:%v", tb, idVal)
		}
	}
	s := fmt.Sprintf("%v", id)
	if len(s) > 2 && s[0] == '{' && s[len(s)-1] == '}' {
		inner := s[1 : len(s)-1]
		if idx := strings.IndexAny(inner, " ,"); idx > 0 {
			return inner[:idx] + ":" + strings.TrimSpace(inner[idx+1:])
		}
	}
	return s
}

func firstRows(results []driver.QueryResult[any]) []any {
	if len(results) == 0 {
		return nil
	}
	switch r := results[0].Result.(type) {
	case []any:
		return r
	case map[string]any:
		return []any{r}
	default:
		return nil
	}
}
