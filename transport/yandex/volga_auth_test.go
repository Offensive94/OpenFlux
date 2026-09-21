package yandex

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"openflux/utils"
)

func TestVolgaCookieJarConcurrentRequestsAndRefresh(t *testing.T) {
	endpoint, _ := url.Parse("https://volga.yandex.ru/session/main/fixture/relay")
	withJar := func(fresh bool) *volgaAuth {
		a := fixtureAuth(fresh)
		a.Session.Jar.SetCookies(endpoint, []*http.Cookie{{Name: "jar-generation", Value: a.Token, Path: "/"}})
		return a
	}
	r := testRelay(t, func(context.Context, string) (*volgaAuth, error) { return withJar(true), nil })
	r.auth.current = cloneVolgaAuth(withJar(false)) // before starting concurrent users
	var closes atomic.Int32
	var oldRequests atomic.Int32
	entered, release := make(chan struct{}, 32), make(chan struct{})
	r.httpClient.Transport = relayRoundTripFunc(func(req *http.Request) (*http.Response, error) {
		defer req.Body.Close()
		cookie, err := req.Cookie("jar-generation")
		token := strings.TrimPrefix(req.Header.Get("Authorization"), "Bearer ")
		if err != nil || cookie.Value != token {
			t.Error("cookie Jar crossed credential generations")
		}
		if token == "old-token" {
			oldRequests.Add(1)
			entered <- struct{}{}
			select {
			case <-release:
			case <-req.Context().Done():
			}
		}
		resp := response(req, 204, &closes)
		resp.Header.Set("Set-Cookie", "relay-seen="+token+"; Path=/")
		return resp, nil
	})
	var callers sync.WaitGroup
	for i := 0; i < 32; i++ {
		callers.Add(1)
		go func() {
			defer callers.Done()
			if err := r.sendBatch([][]byte{[]byte("old")}); err != nil {
				t.Error(err)
			}
			if err := r.sendBatch([][]byte{[]byte("fresh")}); err != nil {
				t.Error(err)
			}
		}()
	}
	for i := 0; i < 32; i++ {
		receive(t, entered)
	}
	old := r.auth.snapshot()
	fresh, err := r.auth.refresh(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	close(release)
	callers.Wait()
	if closes.Load() != 64 || oldRequests.Load() != 32 || r.httpClient.Jar != nil {
		t.Fatal("Jar mutation or concurrent request failure")
	}
	// Late old-generation responses must not contaminate the newly installed Jar.
	for _, snapshot := range []volgaAuthSnapshot{old, fresh} {
		found := false
		for _, c := range snapshot.auth.Session.Jar.Cookies(endpoint) {
			if c.Name == "relay-seen" {
				found = c.Value == snapshot.auth.Token
			}
		}
		if !found {
			t.Fatal("generation-specific Set-Cookie handling was lost")
		}
	}
}

func TestVolgaSnapshotsOwnCookieValues(t *testing.T) {
	input := fixtureAuth(false)
	a := newVolgaAuthState(context.Background(), input, nil)
	defer a.stop()
	input.Token = "mutated"
	input.Cookies[0].Value = "mutated"
	s := a.snapshot()
	if s.auth.Token != "old-token" || s.auth.Cookies[0].Value != "old-cookie" {
		t.Fatal("auth snapshot aliases mutable credential fields")
	}
}

func TestVolgaAuthorizerAndRefreshDoNotLogSecrets(t *testing.T) {
	var logs bytes.Buffer
	oldWriter, oldVerbose := log.Writer(), utils.IsVerbose()
	utils.SetOutput(&logs)
	utils.SetDebug(true)
	defer func() { utils.SetDebug(oldVerbose); utils.SetOutput(oldWriter) }()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch req.URL.Path {
		case "/document":
			cfg, _ := json.Marshal(map[string]any{"officeActionData": map[string]any{
				"action_url": "http://" + req.Host + "/auth?sensitive-action", "access_token": "sensitive-access-token", "access_token_ttl": "42"},
				"editorParams": map[string]any{"idDoc": "fixture-document"}})
			fmt.Fprintf(w, `<script id="client-config">%s</script>`, cfg)
		case "/auth":
			if err := req.ParseForm(); err != nil || req.Form.Get("access_token") != "sensitive-access-token" || req.Form.Get("access_token_ttl") != "42" {
				t.Error("auth form changed")
			}
			data, _ := json.Marshal(map[string]any{"sessionId": "sensitive-session", "userId": 20,
				"xiva": map[string]any{"sign": "sensitive-sign", "ts": "fixture-ts", "user": "fixture-user"}})
			q := url.Values{"token": {"sensitive-relay-token"}, "request-path": {"sensitive-path"}, "json": {string(data)}}
			w.Header().Set("Location", "http://"+req.Host+"/session?"+q.Encode())
			w.WriteHeader(302)
		case "/session":
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "sensitive-cookie", Path: "/"})
			w.WriteHeader(200)
		default:
			fmt.Fprint(w, "missing config containing sensitive-html")
		}
	}))
	defer srv.Close()
	auth, err := authorizeContext(context.Background(), srv.URL+"/document?share=sensitive-share")
	if err != nil || auth.Token != "sensitive-relay-token" || auth.Cookies[0].Value != "sensitive-cookie" {
		t.Fatalf("fake authorization failed: %v", err)
	}
	_, err = authorizeContext(context.Background(), srv.URL+"/bad?sensitive-share")
	if err == nil || strings.Contains(err.Error(), "sensitive") {
		t.Fatal("document failure leaked details")
	}
	a := newVolgaAuthState(context.Background(), fixtureAuth(false), func(context.Context, string) (*volgaAuth, error) { return nil, errors.New("sensitive-refresh-error") })
	_, err = a.refresh(context.Background(), a.snapshot())
	a.stop()
	if err != errVolgaAuthRefresh || strings.Contains(logs.String(), "sensitive") {
		t.Fatal("authorization/refresh logs exposed credential or document details")
	}
}

func TestVolgaAuthorizeContextCancellation(t *testing.T) {
	entered := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) { close(entered); <-req.Context().Done() }))
	defer srv.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := authorizeContext(ctx, srv.URL); result <- err }()
	receive(t, entered)
	cancel()
	if receive(t, result) == nil {
		t.Fatal("cancelled authorization succeeded")
	}
}
