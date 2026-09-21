package yandex

import (
	"context"
	"errors"
	"sync"
	"time"

	"openflux/utils"
)

var errVolgaAuthRefresh = errors.New("Volga session refresh failed")

type volgaAuthorizeFunc func(context.Context, string) (*volgaAuth, error)

// A request uses exactly one immutable credential generation. completed is an
// attempt ticket: requests already in flight share even a FAILED refresh result,
// while a request started after that failure may try again. No cooldown or
// permanent failed state is needed.
type volgaAuthSnapshot struct {
	auth       *volgaAuth
	generation uint64
	completed  uint64
	changed    <-chan struct{}
}

type volgaRefreshAttempt struct {
	id     uint64
	done   chan struct{}
	result volgaAuthSnapshot
	err    error
}

type volgaAuthState struct {
	mu         sync.Mutex
	current    *volgaAuth
	generation uint64
	completed  uint64
	changed    chan struct{}
	last       *volgaRefreshAttempt
	authorize  volgaAuthorizeFunc // immutable after construction
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
}

func newVolgaAuthState(ctx context.Context, auth *volgaAuth, authorize volgaAuthorizeFunc) *volgaAuthState {
	ctx, cancel := context.WithCancel(ctx)
	return &volgaAuthState{current: cloneVolgaAuth(auth), generation: 1,
		changed: make(chan struct{}), authorize: authorize, ctx: ctx, cancel: cancel}
}

func cloneVolgaAuth(auth *volgaAuth) *volgaAuth {
	if auth == nil {
		return nil
	}
	owned := *auth
	owned.Cookies = nil
	for _, c := range auth.Cookies {
		if c == nil {
			continue
		}
		cookie := *c
		cookie.Unparsed = append([]string(nil), c.Unparsed...)
		owned.Cookies = append(owned.Cookies, &cookie)
	}
	return &owned
}

func (a *volgaAuthState) snapshotLocked() volgaAuthSnapshot {
	return volgaAuthSnapshot{a.current, a.generation, a.completed, a.changed}
}

func (a *volgaAuthState) snapshot() volgaAuthSnapshot {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.snapshotLocked()
}

func (a *volgaAuthState) refresh(ctx context.Context, stale volgaAuthSnapshot) (volgaAuthSnapshot, error) {
	a.mu.Lock()
	if err := ctx.Err(); err != nil {
		a.mu.Unlock()
		return volgaAuthSnapshot{}, err
	}
	if err := a.ctx.Err(); err != nil {
		a.mu.Unlock()
		return volgaAuthSnapshot{}, err
	}
	if a.generation != stale.generation {
		fresh := a.snapshotLocked()
		a.mu.Unlock()
		return fresh, nil
	}
	attempt := a.last
	if attempt == nil || stale.completed >= attempt.id {
		attempt = &volgaRefreshAttempt{id: a.completed + 1, done: make(chan struct{})}
		a.last = attempt
		a.wg.Add(1) // serialized with stop; no lock is held across authorize I/O
		go a.runRefresh(attempt, stale.auth)
	}
	a.mu.Unlock()
	select {
	case <-ctx.Done():
		return volgaAuthSnapshot{}, ctx.Err()
	case <-a.ctx.Done():
		return volgaAuthSnapshot{}, a.ctx.Err()
	case <-attempt.done:
		// Cancellation wins even if completion and cancellation raced.
		if err := ctx.Err(); err != nil {
			return volgaAuthSnapshot{}, err
		}
		if err := a.ctx.Err(); err != nil {
			return volgaAuthSnapshot{}, err
		}
		return attempt.result, attempt.err
	}
}

func (a *volgaAuthState) runRefresh(attempt *volgaRefreshAttempt, stale *volgaAuth) {
	defer a.wg.Done()
	ctx, cancel := context.WithTimeout(a.ctx, 30*time.Second)
	defer cancel()
	var fresh *volgaAuth
	err := errVolgaAuthRefresh
	if stale != nil && stale.docURL != "" && a.authorize != nil {
		fresh, err = a.authorize(ctx, stale.docURL)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if err != nil || fresh == nil || ctx.Err() != nil {
		// An authorizer error may contain a document URL, cookie, or signature.
		attempt.err = errVolgaAuthRefresh
		utils.Debugf("[VOLGA] auth refresh failed")
	} else {
		a.current = cloneVolgaAuth(fresh)
		a.generation++
		close(a.changed) // reconnect a live WS with the same new generation
		a.changed = make(chan struct{})
		utils.Debugf("[VOLGA] auth refresh succeeded")
	}
	a.completed = attempt.id
	attempt.result = a.snapshotLocked()
	close(attempt.done)
}

func (a *volgaAuthState) stop() {
	a.mu.Lock()
	a.cancel()
	a.mu.Unlock()
	a.wg.Wait()
}
