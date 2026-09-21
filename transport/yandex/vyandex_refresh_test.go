package yandex

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/cookiejar"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type relayRoundTripFunc func(*http.Request) (*http.Response, error)

func (f relayRoundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fixtureAuth(fresh bool) *volgaAuth {
	label, uid := "old", 10
	if fresh {
		label, uid = "fresh", 20
	}
	jar, _ := cookiejar.New(nil)
	return &volgaAuth{docURL: "https://document.invalid/fixture", DocID: "same-document",
		Session: &http.Client{Jar: jar}, Token: label + "-token", RequestPath: label + "-path", UserID: uid,
		UserIDStr: label + "-user", Sign: label + "-sign", TS: label + "-ts", SessionID: label + "-session",
		Cookies: []*http.Cookie{{Name: "session", Value: label + "-cookie"}}}
}

func testRelay(t *testing.T, authorize volgaAuthorizeFunc) *relayClient {
	t.Helper()
	cfg := DefaultVolgaConfig()
	cfg.WorkerCount, cfg.QueueSize, cfg.BatchSize = 1, 8, 1
	cfg.ReconnectMinDelay, cfg.ReconnectMaxDelay = time.Millisecond, time.Millisecond
	r := newRelayClient(fixtureAuth(false), cfg, &VolgaStats{})
	r.auth.authorize = authorize // inject before any goroutine observes the state
	t.Cleanup(r.Stop)
	return r
}

func receive[T any](t *testing.T, ch <-chan T) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for test barrier")
	}
	var zero T
	return zero
}

type trackedResponseBody struct {
	io.Reader
	closes *atomic.Int32
}

func (b trackedResponseBody) Close() error { b.closes.Add(1); return nil }

func response(req *http.Request, status int, closes *atomic.Int32) *http.Response {
	return &http.Response{StatusCode: status, Header: make(http.Header), Request: req,
		Body: trackedResponseBody{strings.NewReader("synthetic response"), closes}}
}

type relayPayload struct {
	Message struct {
		BundleID uint64            `json:"bundleId"`
		Bundle   []json.RawMessage `json:"bundle"`
	} `json:"message"`
}

func checkRelayRequest(t *testing.T, req *http.Request, fresh bool) (relayPayload, []byte) {
	t.Helper()
	a := fixtureAuth(fresh)
	if req.Header.Get("Authorization") != "Bearer "+a.Token || req.URL.Path != "/session/main/"+a.RequestPath+"/relay" ||
		req.Header.Get("Cookie") != "session="+a.Cookies[0].Value || !strings.HasSuffix(req.Referer(), a.RequestPath) {
		t.Error("request mixed credential generations")
	}
	defer req.Body.Close()
	var p relayPayload
	if err := json.NewDecoder(req.Body).Decode(&p); err != nil || len(p.Message.Bundle) != 3 {
		t.Error("invalid relay bundle")
		return p, nil
	}
	var op struct {
		ID  string              `json:"id"`
		Ops [][]json.RawMessage `json:"ops"`
	}
	if err := json.Unmarshal(p.Message.Bundle[1], &op); err != nil || len(op.Ops) != 1 || len(op.Ops[0]) < 2 {
		t.Error("invalid caret operation")
		return p, nil
	}
	var uid int
	if err := json.Unmarshal(op.Ops[0][1], &uid); err != nil || uid != a.UserID {
		t.Error("stale payload UserID")
	}
	var encoded string
	if err := json.Unmarshal(p.Message.Bundle[2], &encoded); err != nil {
		t.Error(err)
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Error(err)
	}
	return p, data
}

// This test failed against the exact PR #79 base: attempts=1, status 401.
func TestVolgaRelay401Recovery(t *testing.T) {
	var refreshes, closes atomic.Int32
	r := testRelay(t, func(context.Context, string) (*volgaAuth, error) { refreshes.Add(1); return fixtureAuth(true), nil })
	var attempts int
	var first []byte
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		_, data := checkRelayRequest(t, req, attempts == 2)
		if attempts == 1 {
			first = data
			return response(req, 401, &closes), nil
		}
		if !bytes.Equal(first, data) {
			t.Error("retry changed the logical batch")
		}
		return response(req, 204, &closes), nil
	})
	if err := r.sendBatch([][]byte{[]byte("synthetic packet")}); err != nil {
		t.Fatal(err)
	}
	if attempts != 2 || refreshes.Load() != 1 || closes.Load() != 2 || r.stats.PacketsSent.Load() != 1 || r.stats.PacketsBatched.Load() != 1 {
		t.Fatal("recovery was not exactly one refresh/retry and one logical success")
	}
	if r.httpClient.Jar != nil {
		t.Fatal("relay client still depends on mutable Jar")
	}
}

func TestVolgaRelayStatusPolicy(t *testing.T) {
	for _, tc := range []struct {
		name                       string
		status, retryStatus        int
		refreshError, networkError bool
		attempts, refreshes        int
		success                    bool
	}{
		{"normal_204", 204, 0, false, false, 1, 0, true},
		{"normal_200", 200, 0, false, false, 1, 0, true},
		{"401_refresh_200", 401, 200, false, false, 2, 1, true},
		{"401_refresh_error", 401, 0, true, false, 1, 1, false},
		{"401_refresh_401", 401, 401, false, false, 2, 1, false},
		{"403_no_refresh", 403, 0, false, false, 1, 0, false},
		{"429_no_refresh", 429, 0, false, false, 1, 0, false},
		{"500_no_refresh", 500, 0, false, false, 1, 0, false},
		{"network_error_no_retry", 0, 0, false, true, 1, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var attempts, refreshes, closes atomic.Int32
			r := testRelay(t, func(context.Context, string) (*volgaAuth, error) {
				refreshes.Add(1)
				if tc.refreshError {
					return nil, errors.New("synthetic-sensitive-authorization")
				}
				return fixtureAuth(true), nil
			})
			r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				n := attempts.Add(1)
				checkRelayRequest(t, req, n == 2)
				if tc.networkError {
					return nil, errors.New("synthetic-sensitive-network-error")
				}
				status := tc.status
				if n == 2 {
					status = tc.retryStatus
				}
				return response(req, status, &closes), nil
			})
			err := r.sendBatch([][]byte{[]byte("fixture")})
			if (err == nil) != tc.success || int(attempts.Load()) != tc.attempts || int(refreshes.Load()) != tc.refreshes {
				t.Fatalf("wrong status policy: %v", err)
			}
			if err != nil && strings.Contains(err.Error(), "sensitive") {
				t.Fatal("raw dependency error leaked")
			}
			if !tc.networkError && closes.Load() != attempts.Load() {
				t.Fatal("response body leaked")
			}
		})
	}
}

func TestVolgaConcurrent401(t *testing.T) {
	for _, failure := range []bool{false, true} {
		name := "success"
		if failure {
			name = "failure"
		}
		t.Run(name, func(t *testing.T) {
			const n = 100
			entered, release401 := make(chan struct{}, n), make(chan struct{})
			authStarted, releaseAuth := make(chan struct{}, 2), make(chan struct{})
			var refreshes, attempts, closes atomic.Int32
			r := testRelay(t, func(ctx context.Context, _ string) (*volgaAuth, error) {
				call := refreshes.Add(1)
				authStarted <- struct{}{}
				select {
				case <-releaseAuth:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
				if failure && call == 1 {
					return nil, errors.New("synthetic refresh failure")
				}
				return fixtureAuth(true), nil
			})
			r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
				attempts.Add(1)
				fresh := req.Header.Get("Authorization") == "Bearer fresh-token"
				checkRelayRequest(t, req, fresh)
				if !fresh {
					entered <- struct{}{}
					select {
					case <-release401:
					case <-req.Context().Done():
						return nil, req.Context().Err()
					}
					return response(req, 401, &closes), nil
				}
				return response(req, 204, &closes), nil
			})
			results := make(chan error, n)
			for i := 0; i < n; i++ {
				go func() { results <- r.sendBatch([][]byte{[]byte("packet")}) }()
			}
			for i := 0; i < n; i++ {
				receive(t, entered)
			} // all requests hold generation 1/attempt ticket 0
			close(release401)
			receive(t, authStarted)
			close(releaseAuth)
			for i := 0; i < n; i++ {
				err := receive(t, results)
				if failure && err != errVolgaAuthRefresh || !failure && err != nil {
					t.Fatal("refresh wave had inconsistent result")
				}
			}
			if refreshes.Load() != 1 {
				t.Fatal("refresh stampede")
			}
			want := int32(n * 2)
			if failure {
				want = n
			}
			if attempts.Load() != want || closes.Load() != want {
				t.Fatal("wrong HTTP attempts/body closes")
			}
			if failure {
				if err := r.sendBatch([][]byte{[]byte("new independent attempt")}); err != nil || refreshes.Load() != 2 {
					t.Fatal("failure permanently poisoned auth")
				}
			}
			if r.auth.snapshot().generation != 2 || r.httpClient.Jar != nil {
				t.Fatal("expected one fresh generation without client Jar mutation")
			}
		})
	}
}

func TestVolgaRefreshCancellation(t *testing.T) {
	started, release := make(chan struct{}), make(chan struct{})
	a := newVolgaAuthState(context.Background(), fixtureAuth(false), func(ctx context.Context, _ string) (*volgaAuth, error) {
		close(started)
		select {
		case <-release:
			return fixtureAuth(true), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	})
	defer a.stop()
	snapshot := a.snapshot()
	ctx, cancel := context.WithCancel(context.Background())
	first, other := make(chan error, 1), make(chan error, 1)
	go func() { _, err := a.refresh(ctx, snapshot); first <- err }()
	receive(t, started)
	go func() { _, err := a.refresh(context.Background(), snapshot); other <- err }()
	cancel()
	if !errors.Is(receive(t, first), context.Canceled) {
		t.Fatal("cancelled waiter stayed blocked")
	}
	close(release)
	if err := receive(t, other); err != nil {
		t.Fatal("one waiter cancelled shared refresh")
	}
}

func TestVolgaStopCancelsRefreshWithoutRetry(t *testing.T) {
	started := make(chan struct{})
	var attempts, closes atomic.Int32
	r := testRelay(t, func(ctx context.Context, _ string) (*volgaAuth, error) {
		close(started)
		<-ctx.Done()
		return nil, ctx.Err()
	})
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		req.Body.Close()
		return response(req, 401, &closes), nil
	})
	result := make(chan error, 1)
	go func() { result <- r.sendBatch([][]byte{[]byte("packet")}) }()
	receive(t, started)
	stopped := make(chan struct{})
	go func() { r.Stop(); close(stopped) }()
	receive(t, stopped)
	if receive(t, result) == nil || attempts.Load() != 1 || closes.Load() != 1 {
		t.Fatal("Stop leaked a waiter or retried")
	}
	if err := r.Send([]byte("after stop")); err == nil {
		t.Fatal("stopped Send accepted a packet")
	}
}

func TestVolgaSessionStatePreserved(t *testing.T) {
	r := testRelay(t, func(context.Context, string) (*volgaAuth, error) { return fixtureAuth(true), nil })
	r.SetFrontier("1-99.42")
	r.bundleID.Store(50)
	r.seq.Store(60)
	r.localID.Store(70)
	var attempts int
	var closes atomic.Int32
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts++
		p, _ := checkRelayRequest(t, req, attempts == 2)
		var op struct {
			ID       string   `json:"id"`
			LocalID  uint64   `json:"localId"`
			Frontier []string `json:"frontier"`
		}
		if err := json.Unmarshal(p.Message.Bundle[0], &op); err != nil {
			t.Error(err)
		}
		wantID := "1-10.61"
		if attempts == 2 {
			wantID = "1-20.63"
		}
		if p.Message.BundleID != uint64(50+attempts) || op.LocalID != uint64(69+attempts*2) || op.ID != wantID || !reflect.DeepEqual(op.Frontier, []string{"1-99.42"}) {
			t.Error("refresh reset document frontier or reused operation IDs")
		}
		status := 401
		if attempts == 2 {
			status = 204
		}
		return response(req, status, &closes), nil
	})
	if err := r.sendBatch([][]byte{[]byte("packet")}); err != nil {
		t.Fatal(err)
	}
}

func TestVolgaWorkerCountsRecoveredBatchOnce(t *testing.T) {
	var attempts, closes atomic.Int32
	r := testRelay(t, func(context.Context, string) (*volgaAuth, error) { return fixtureAuth(true), nil })
	done := make(chan struct{})
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		n := attempts.Add(1)
		req.Body.Close()
		status := 401
		if n == 2 {
			status = 204
			close(done)
		}
		return response(req, status, &closes), nil
	})
	r.Start()
	if err := r.Send([]byte("packet")); err != nil {
		t.Fatal(err)
	}
	receive(t, done)
	r.Stop() // joins the worker; stats must be settled now
	if r.stats.HTTPReqsFailed.Load() != 0 || r.stats.HTTPReqsSent.Load() != 1 || r.stats.BatchesSent.Load() != 1 || r.stats.PacketsSent.Load() != 1 {
		t.Fatal("recovered 401 counted as logical failure or double success")
	}
}

func TestVolgaStopAndSendDoNotRaceOnClosedQueue(t *testing.T) {
	r := testRelay(t, nil)
	var senders sync.WaitGroup
	for i := 0; i < 32; i++ {
		senders.Add(1)
		go func() {
			defer senders.Done()
			for j := 0; j < 100; j++ {
				_ = r.Send([]byte("packet"))
			}
		}()
	}
	r.Stop()
	senders.Wait()
	r.Stop()
}

func TestVolgaResponseDrainIsBounded(t *testing.T) {
	reader := strings.NewReader(strings.Repeat("x", 128<<10))
	var closes atomic.Int32
	drainVolgaResponse(trackedResponseBody{reader, &closes})
	if reader.Len() != 64<<10 || closes.Load() != 1 {
		t.Fatal("unbounded drain or leaked body")
	}
}

type cancelOnRead struct {
	cancel context.CancelFunc
	closes *atomic.Int32
}

func (b cancelOnRead) Read([]byte) (int, error) { b.cancel(); return 0, context.Canceled }
func (b cancelOnRead) Close() error             { b.closes.Add(1); return nil }

func TestVolgaCancelled401BodyIsClosedWithoutRefresh(t *testing.T) {
	var closes, attempts, refreshes atomic.Int32
	r := testRelay(t, func(context.Context, string) (*volgaAuth, error) { refreshes.Add(1); return fixtureAuth(true), nil })
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		attempts.Add(1)
		req.Body.Close()
		resp := response(req, 401, &closes)
		resp.Body = cancelOnRead{r.cancel, &closes}
		return resp, nil
	})
	if err := r.sendBatch([][]byte{[]byte("packet")}); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation was not observed")
	}
	if attempts.Load() != 1 || closes.Load() != 1 || refreshes.Load() != 0 {
		t.Fatal("cancelled 401 leaked a body or retried")
	}
}
