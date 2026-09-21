package yandex

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gorilla/websocket"
)

func checkWSAuth(t *testing.T, wsURL string, header http.Header, fresh bool) {
	t.Helper()
	u, err := url.Parse(wsURL)
	if err != nil {
		t.Error(err)
		return
	}
	a := fixtureAuth(fresh)
	for k, v := range map[string]string{"user": a.UserIDStr, "sign": a.Sign, "ts": a.TS, "session": a.SessionID} {
		if u.Query().Get(k) != v {
			t.Errorf("stale WS field %s", k)
		}
	}
	if header.Get("Cookie") != "session="+a.Cookies[0].Value {
		t.Error("stale WS cookies")
	}
}

func TestVolgaWSAndHTTPShareRefresh(t *testing.T) {
	var refreshes, closes atomic.Int32
	oldWS, oldHTTP, authorizeStarted := make(chan struct{}), make(chan struct{}), make(chan struct{}, 2)
	releaseFailure, releaseAuth, freshWS := make(chan struct{}), make(chan struct{}), make(chan struct{}, 2)
	r := testRelay(t, func(ctx context.Context, _ string) (*volgaAuth, error) {
		refreshes.Add(1)
		authorizeStarted <- struct{}{}
		select {
		case <-releaseAuth:
			return fixtureAuth(true), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	w := newWSListener(r.config, r.stats, r, nil)
	w.dial = func(ctx context.Context, u string, h http.Header) (*websocket.Conn, *http.Response, error) {
		fresh := strings.Contains(u, "fresh-user")
		checkWSAuth(t, u, h, fresh)
		if fresh {
			freshWS <- struct{}{}
			<-ctx.Done()
		} else {
			close(oldWS)
			select {
			case <-releaseFailure:
			case <-ctx.Done():
			}
		}
		return nil, nil, errors.New("synthetic socket failure")
	}
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		fresh := req.Header.Get("Authorization") == "Bearer fresh-token"
		checkRelayRequest(t, req, fresh)
		if fresh {
			return response(req, 204, &closes), nil
		}
		close(oldHTTP)
		select {
		case <-releaseFailure:
		case <-req.Context().Done():
		}
		return response(req, 401, &closes), nil
	})
	w.Start()
	defer w.Stop()
	result := make(chan error, 1)
	go func() { result <- r.sendBatch([][]byte{[]byte("packet")}) }()
	receive(t, oldWS)
	receive(t, oldHTTP)
	close(releaseFailure)
	receive(t, authorizeStarted)
	close(releaseAuth)
	if err := receive(t, result); err != nil {
		t.Fatal(err)
	}
	receive(t, freshWS)
	if w.auth != r.auth || refreshes.Load() != 1 || r.auth.snapshot().generation != 2 {
		t.Fatal("WS/HTTP refresh did not coalesce")
	}
}

func TestVolgaWSRefreshVisibleToRelay(t *testing.T) {
	var refreshes, closes atomic.Int32
	r := testRelay(t, func(context.Context, string) (*volgaAuth, error) { refreshes.Add(1); return fixtureAuth(true), nil })
	w := newWSListener(r.config, r.stats, r, nil)
	freshDial := make(chan struct{}, 1)
	w.dial = func(ctx context.Context, u string, h http.Header) (*websocket.Conn, *http.Response, error) {
		fresh := strings.Contains(u, "fresh-user")
		checkWSAuth(t, u, h, fresh)
		if fresh {
			freshDial <- struct{}{}
			<-ctx.Done()
		}
		return nil, nil, errors.New("synthetic disconnect")
	}
	w.Start()
	defer w.Stop()
	receive(t, freshDial)
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		checkRelayRequest(t, req, true)
		return response(req, 204, &closes), nil
	})
	if err := r.sendBatch([][]byte{[]byte("packet")}); err != nil || refreshes.Load() != 1 {
		t.Fatal("relay missed WS refresh")
	}
}

func TestVolgaHTTPRefreshReconnectsLiveWS(t *testing.T) {
	connected := make(chan struct{}, 3)
	var connects atomic.Int32
	upgrader := websocket.Upgrader{CheckOrigin: func(*http.Request) bool { return true }} // loopback only
	srv := httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, req *http.Request) {
		conn, err := upgrader.Upgrade(rw, req, nil)
		if err != nil {
			return
		}
		defer conn.Close()
		connected <- struct{}{}
		for {
			if _, _, err := conn.ReadMessage(); err != nil {
				return
			}
		}
	}))
	defer srv.Close()
	var refreshes, closes atomic.Int32
	r := testRelay(t, func(context.Context, string) (*volgaAuth, error) { refreshes.Add(1); return fixtureAuth(true), nil })
	w := newWSListener(r.config, r.stats, r, nil)
	w.dial = func(ctx context.Context, u string, h http.Header) (*websocket.Conn, *http.Response, error) {
		checkWSAuth(t, u, h, connects.Add(1) == 2)
		return websocket.DefaultDialer.DialContext(ctx, "ws"+strings.TrimPrefix(srv.URL, "http"), h)
	}
	w.Start()
	defer w.Stop()
	receive(t, connected)
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		fresh := req.Header.Get("Authorization") == "Bearer fresh-token"
		checkRelayRequest(t, req, fresh)
		status := 401
		if fresh {
			status = 204
		}
		return response(req, status, &closes), nil
	})
	if err := r.sendBatch([][]byte{[]byte("packet")}); err != nil {
		t.Fatal(err)
	}
	receive(t, connected)
	if connects.Load() != 2 || refreshes.Load() != 1 {
		t.Fatal("live WS refresh caused duplicate auth or dial loop")
	}
}

func TestVolgaWSStopDuringSharedRefresh(t *testing.T) {
	started := make(chan struct{})
	r := testRelay(t, func(ctx context.Context, _ string) (*volgaAuth, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	w := newWSListener(r.config, r.stats, r, nil)
	w.dial = func(context.Context, string, http.Header) (*websocket.Conn, *http.Response, error) {
		return nil, nil, errors.New("synthetic disconnect")
	}
	w.Start()
	receive(t, started)
	done := make(chan struct{})
	go func() { w.Stop(); r.Stop(); close(done) }()
	receive(t, done)
}

func TestVolgaWSCredentialsAreQueryEscaped(t *testing.T) {
	r := testRelay(t, nil)
	auth := fixtureAuth(false)
	auth.Sign, auth.TS, auth.SessionID = "fixture+sign&=", "fixture+ts&=", "fixture+session&="
	r.auth.current = cloneVolgaAuth(auth)
	w := newWSListener(r.config, r.stats, r, nil)
	defer w.Stop()
	w.dial = func(_ context.Context, raw string, _ http.Header) (*websocket.Conn, *http.Response, error) {
		u, _ := url.Parse(raw)
		if u.Query().Get("sign") != auth.Sign || u.Query().Get("ts") != auth.TS || u.Query().Get("session") != auth.SessionID {
			t.Error("WS query changed a credential value")
		}
		return nil, nil, errors.New("synthetic failure")
	}
	if err := w.connect(r.auth.snapshot()); err == nil {
		t.Fatal("unexpected socket success")
	}
}
