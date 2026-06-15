// Package session implements an [engine.Authenticator] that validates
// session-based authentication.
//
// Session IDs are carried in gRPC metadata (or HTTP headers) under the
// "X-Session-Id" key (configurable via [WithSessionIDHeader]).
//
// The session store is pluggable via the [SessionStore] interface.
// An in-memory store is used by default. For production use, a Redis
// or database-backed implementation should be provided via [WithStore].
//
// Usage:
//
//	store := session.NewMemoryStore()
//	auth, _ := session.NewAuthenticator(session.WithStore(store))
//	// Create a session:
//	id, _ := store.Set("", map[string]interface{}{"sub": "alice"})
//	// Authenticate:
//	ctx = session.ContextWithSessionID(ctx, id)
//	claims, err := auth.Authenticate(ctx)
package session

import (
	"context"
	"sync"

	"github.com/tx7do/kratos-authn/engine"
)

// context key type for session ID.
type ctxKey string

const sessionIDKey ctxKey = "session-id"

// ContextWithSessionID injects a session ID into the context.
func ContextWithSessionID(parent context.Context, sessionID string) context.Context {
	return context.WithValue(parent, sessionIDKey, sessionID)
}

// SessionIDFromContext extracts the session ID from the context.
func SessionIDFromContext(ctx context.Context) (string, bool) {
	id, ok := ctx.Value(sessionIDKey).(string)
	return id, ok
}

// ---------------------------------------------------------------------------
// MemoryStore — a thread-safe in-memory SessionStore implementation.
// ---------------------------------------------------------------------------

// MemoryStore is a simple in-memory session store for development/testing.
type MemoryStore struct {
	mu       sync.RWMutex
	sessions map[string]map[string]interface{}
}

// NewMemoryStore creates a new in-memory session store.
func NewMemoryStore() *MemoryStore {
	return &MemoryStore{
		sessions: make(map[string]map[string]interface{}),
	}
}

func (m *MemoryStore) Get(sessionID string) (map[string]interface{}, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	claims, ok := m.sessions[sessionID]
	return claims, ok
}

func (m *MemoryStore) Set(sessionID string, claims map[string]interface{}) (string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sessionID == "" {
		sessionID = generateSessionID()
	}
	m.sessions[sessionID] = claims
	return sessionID, nil
}

func (m *MemoryStore) Delete(sessionID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.sessions, sessionID)
}

// defaultMemoryStore is the fallback store when none is configured.
var defaultMemoryStore = NewMemoryStore()

func generateSessionID() string {
	return generateRandomString(32)
}

// generateRandomString produces a random hex string of the given byte length.
func generateRandomString(n int) string {
	const hexChars = "0123456789abcdef"
	b := make([]byte, n)
	for i := range b {
		b[i] = hexChars[fastRand()%16]
	}
	return string(b)
}

var randCounter uint64
var randMu sync.Mutex

func fastRand() int {
	randMu.Lock()
	defer randMu.Unlock()
	randCounter = randCounter*6364136223846793005 + 1442695040888963407
	return int(randCounter >> 32)
}

// ---------------------------------------------------------------------------
// Authenticator
// ---------------------------------------------------------------------------

// Authenticator validates session-based authentication.
type Authenticator struct {
	options *Options
}

var _ engine.Authenticator = (*Authenticator)(nil)

// NewAuthenticator creates a session authenticator from the given options.
func NewAuthenticator(opts ...Option) (engine.Authenticator, error) {
	o := &Options{}
	for _, opt := range opts {
		opt(o)
	}
	return &Authenticator{options: o}, nil
}

// Authenticate extracts the session ID from the context (via either
// ContextWithSessionID or gRPC metadata) and validates it against the
// session store.
func (a *Authenticator) Authenticate(ctx context.Context, _ engine.ContextType) (*engine.AuthClaims, error) {
	sessionID, ok := SessionIDFromContext(ctx)
	if !ok || sessionID == "" {
		return nil, engine.ErrMissingBearerToken
	}
	return a.AuthenticateToken(sessionID)
}

// AuthenticateToken looks up the session ID in the store and returns
// the associated claims.
func (a *Authenticator) AuthenticateToken(sessionID string) (*engine.AuthClaims, error) {
	if sessionID == "" {
		return nil, engine.ErrMissingBearerToken
	}

	claims, ok := a.options.getStore().Get(sessionID)
	if !ok {
		return nil, engine.ErrUnauthenticated
	}

	c := engine.AuthClaims(claims)
	return &c, nil
}

// CreateIdentityWithContext creates a session and injects the session ID
// into the context.
func (a *Authenticator) CreateIdentityWithContext(ctx context.Context, _ engine.ContextType, claims engine.AuthClaims) (context.Context, error) {
	sessionID, err := a.CreateIdentity(claims)
	if err != nil {
		return ctx, err
	}
	ctx = ContextWithSessionID(ctx, sessionID)
	return ctx, nil
}

// CreateIdentity creates a new session from the claims and returns the session ID.
func (a *Authenticator) CreateIdentity(claims engine.AuthClaims) (string, error) {
	// Convert AuthClaims (map[string]interface{}) to map[string]interface{}
	data := map[string]interface{}(claims)
	return a.options.getStore().Set("", data)
}

func (a *Authenticator) Close() {}
