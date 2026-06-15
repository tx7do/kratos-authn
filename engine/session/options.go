package session

// SessionStore is the interface for storing and retrieving session data
// by session ID. Implementations can use memory, Redis, a database, etc.
type SessionStore interface {
	// Get retrieves the claims associated with the session ID.
	// Returns (nil, false) if the session does not exist or has expired.
	Get(sessionID string) (claims map[string]interface{}, ok bool)

	// Set stores claims for a session ID and returns the ID to use.
	// If sessionID is empty, the store should generate one.
	Set(sessionID string, claims map[string]interface{}) (id string, err error)

	// Delete removes a session.
	Delete(sessionID string)
}

// Options holds configuration for the session authenticator.
type Options struct {
	// store is the session store. If nil, an in-memory store is used.
	store SessionStore

	// sessionIDHeader is the gRPC metadata key used to carry the session ID.
	// Defaults to "X-Session-Id".
	sessionIDHeader string
}

type Option func(o *Options)

// WithStore sets the session store implementation.
func WithStore(s SessionStore) Option {
	return func(o *Options) { o.store = s }
}

// WithSessionIDHeader overrides the metadata key for the session ID.
func WithSessionIDHeader(name string) Option {
	return func(o *Options) { o.sessionIDHeader = name }
}

func (o *Options) getStore() SessionStore {
	if o.store != nil {
		return o.store
	}
	return defaultMemoryStore
}

func (o *Options) getSessionIDHeader() string {
	if o.sessionIDHeader != "" {
		return o.sessionIDHeader
	}
	return "X-Session-Id"
}
