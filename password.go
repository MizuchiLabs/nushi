package nushi

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/json/v2"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"
)

const (
	// A guesser cannot lock the owner out with loginAttempts per client. A crowd gets no more than loginCap,
	// and the local network has a cap of its own, so a crowd outside cannot lock the owner out at home.
	loginAttempts = 5
	loginCap      = 30
	loginWindow   = time.Minute
)

type limiter struct {
	mu    sync.Mutex
	since time.Time
	total map[bool]int // keyed by whether the client is local
	tries map[netip.Prefix]int
}

func (g *Guard) signIn(w http.ResponseWriter, r *http.Request) {
	from := g.clientAddr(r)
	if !g.limiter.attempt(from) {
		writeProblem(w, http.StatusTooManyRequests, "too many tries, wait a minute")
		return
	}
	var body struct {
		Password string `json:"password"`
	}
	if err := json.UnmarshalRead(http.MaxBytesReader(w, r.Body, 4096), &body); err != nil {
		writeProblem(w, http.StatusBadRequest, "send the password as JSON")
		return
	}
	given := sha256.Sum256([]byte(body.Password))
	if subtle.ConstantTimeCompare(given[:], g.password[:]) != 1 {
		slog.Warn("wrong password", "client", from)
		writeProblem(w, http.StatusUnauthorized, "wrong password")
		return
	}
	g.limiter.refund(from)
	g.startSession(w, r)
	w.WriteHeader(http.StatusNoContent)
}

// attempt takes a try from the client's budget and its pool, and reports whether both had one.
func (l *limiter) attempt(from netip.Addr) bool {
	key, pool := budgetKey(from), local(from)
	l.mu.Lock()
	defer l.mu.Unlock()
	if now := time.Now(); now.Sub(l.since) >= loginWindow {
		l.since = now
		clear(l.total)
		clear(l.tries)
	}
	// A try that is turned away costs nothing, or one client could spend the shared budget.
	if l.total[pool] >= loginCap || l.tries[key] >= loginAttempts {
		return false
	}
	l.total[pool]++
	l.tries[key]++
	return true
}

// refund gives the try back after the right password, so a sign in on every device fits.
func (l *limiter) refund(from netip.Addr) {
	key, pool := budgetKey(from), local(from)
	l.mu.Lock()
	defer l.mu.Unlock()
	l.total[pool] = max(l.total[pool]-1, 0)
	if n := l.tries[key] - 1; n > 0 {
		l.tries[key] = n
	} else {
		delete(l.tries, key)
	}
}

// budgetKey groups a client's addresses, an IPv6 host usually holds a whole /64. Odd addresses share one.
func budgetKey(addr netip.Addr) netip.Prefix {
	bits := 32
	if addr.Is6() {
		bits = 64
	}
	p, _ := addr.Prefix(bits)
	return p
}
