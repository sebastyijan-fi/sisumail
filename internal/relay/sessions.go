package relay

import (
	"net"
	"sync"

	"golang.org/x/crypto/ssh"
)

// Session represents a live SSH connection for a username.
// We keep it minimal; it is the unit the Tier 1 proxy targets.
type Session struct {
	Username string
	// Conn is the underlying SSH connection used to open channels.
	Conn SSHChannelOpener
}

type SSHChannelOpener interface {
	OpenChannel(name string, data []byte) (ch ssh.Channel, reqs <-chan *ssh.Request, err error)
}

type SessionRegistry struct {
	mu       sync.RWMutex
	byUser   map[string]*Session
	byDestV6 map[string]string // dest IPv6 string -> username
}

func NewSessionRegistry() *SessionRegistry {
	return &SessionRegistry{
		byUser:   make(map[string]*Session),
		byDestV6: make(map[string]string),
	}
}

func (r *SessionRegistry) SetUserDestIPv6(username string, ip net.IP) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byDestV6[ip.String()] = username
}

func (r *SessionRegistry) GetUserByDestIPv6(ip net.IP) (string, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	u, ok := r.byDestV6[ip.String()]
	return u, ok
}

func (r *SessionRegistry) SetSession(username string, s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.byUser[username] = s
}

func (r *SessionRegistry) DeleteSession(username string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.byUser, username)
}

func (r *SessionRegistry) GetSession(username string) (*Session, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	s, ok := r.byUser[username]
	return s, ok
}

func (r *SessionRegistry) OnlineUsers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	out := make([]string, 0, len(r.byUser))
	for u := range r.byUser {
		out = append(out, u)
	}
	return out
}
