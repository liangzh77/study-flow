package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
)

const testState = `{"tasks":[{"id":"task-1","title":"复习数学","subtasks":[]}],"blocks":[],"focusLog":{},"focusByTask":{},"timer":{"mode":"focus","focusMin":25,"breakMin":5,"remainingSec":1500}}`

type client struct {
	t    *testing.T
	http *http.Client
	base string
}

func (c client) request(method, path, body string, want int) []byte {
	c.t.Helper()
	req, err := http.NewRequest(method, c.base+path, bytes.NewBufferString(body))
	if err != nil {
		c.t.Fatal(err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.http.Do(req)
	if err != nil {
		c.t.Fatal(err)
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(res.Body)
	if res.StatusCode != want {
		c.t.Fatalf("%s %s: status %d, want %d: %s", method, path, res.StatusCode, want, data)
	}
	return data
}
func newClient(t *testing.T, base string) client {
	jar, _ := cookiejar.New(nil)
	return client{t, &http.Client{Jar: jar}, base}
}
func credentials(name, password string) string {
	b, _ := json.Marshal(map[string]string{"username": name, "password": password})
	return string(b)
}
func stateBody(revision int) string {
	return fmt.Sprintf(`{"revision":%d,"data":%s}`, revision, testState)
}
func TestAccountsAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "study.db")
	db, err := openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer((&server{db: db}).routes())
	defer func() { srv.Close(); db.Close() }()
	anonymous := newClient(t, srv.URL)
	anonymous.request("GET", "/api/state", "", 401)
	alice, bob, admin := newClient(t, srv.URL), newClient(t, srv.URL), newClient(t, srv.URL)
	raw := alice.request("POST", "/api/register", credentials("alice", "secret123"), 200)
	var a user
	json.Unmarshal(raw, &a)
	bob.request("POST", "/api/register", credentials("bob", "secret456"), 200)
	anonymous.request("POST", "/api/register", credentials("ALICE", "123456"), 409)
	anonymous.request("POST", "/api/register", credentials("admin", "123456"), 409)
	alice.request("GET", "/api/admin/users", "", 403)
	alice.request("DELETE", fmt.Sprintf("/api/admin/users/%d", a.ID), "", 403)
	alice.request("PUT", "/api/state", stateBody(5), 409)
	alice.request("PUT", "/api/state", stateBody(0), 200)
	alice.request("PUT", "/api/state", stateBody(0), 409)
	alice.request("PUT", "/api/state", `{"revision":1,"data":{"tasks":[]}}`, 400)
	alice.request("PUT", "/api/state", `{"revision":1,"data":`+string(bytes.ReplaceAll([]byte(testState), []byte(`"title":"复习数学"`), []byte(`"title":"复习数学","estimate":"<img src=x onerror=alert(1)>"`)))+`}`, 400)
	if got := bob.request("GET", "/api/state", "", 200); !bytes.Contains(got, []byte(`"data":null`)) {
		t.Fatalf("cross-user leak: %s", got)
	}
	// Restart the service against the same file; sessions and learning data persist.
	srv.Close()
	db.Close()
	db, err = openDB(path)
	if err != nil {
		t.Fatal(err)
	}
	srv = httptest.NewServer((&server{db: db}).routes())
	alice.base = srv.URL
	bob.base = srv.URL
	admin.base = srv.URL
	anonymous.base = srv.URL
	if got := alice.request("GET", "/api/state", "", 200); !bytes.Contains(got, []byte("复习数学")) {
		t.Fatalf("data missing after restart: %s", got)
	}
	admin.request("POST", "/api/login", credentials("admin", "110623"), 200)
	admin.request("GET", "/api/admin/users", "", 200)
	admin.request("DELETE", "/api/admin/users/1", "", 403)
	admin.request("POST", "/api/admin/users/1/reset-password", "", 403)
	admin.request("POST", fmt.Sprintf("/api/admin/users/%d/reset-password", a.ID), "", 200)
	alice.request("GET", "/api/me", "", 401)
	alice.request("POST", "/api/login", credentials("alice", "secret123"), 401)
	alice.request("POST", "/api/login", credentials("alice", "alice"), 200)
	alice.request("POST", "/api/password", `{"current":"wrong","password":"changed123"}`, 400)
	alice.request("POST", "/api/password", `{"current":"alice","password":"changed123"}`, 200)
	alice.request("GET", "/api/me", "", 401)
	alice.request("POST", "/api/login", credentials("alice", "changed123"), 200)
	admin.request("DELETE", fmt.Sprintf("/api/admin/users/%d", a.ID), "", 200)
	alice.request("GET", "/api/state", "", 401)
	alice.request("POST", "/api/login", credentials("alice", "changed123"), 401)
	for _, table := range []string{"states", "sessions"} {
		var count int
		if err = db.QueryRow("SELECT count(*) FROM "+table+" WHERE user_id=?", a.ID).Scan(&count); err != nil || count != 0 {
			t.Fatalf("%s not cascaded: %d %v", table, count, err)
		}
	}
	bob.request("POST", "/api/logout", "", 200)
	bob.request("GET", "/api/me", "", 401)
	req, _ := http.NewRequest("POST", srv.URL+"/api/login", bytes.NewBufferString(credentials("bob", "secret456")))
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Content-Type", "application/json")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != 403 {
		t.Fatalf("cross-site login accepted: %d", res.StatusCode)
	}
}
func TestConcurrentWrites(t *testing.T) {
	db, err := openDB(filepath.Join(t.TempDir(), "study.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := httptest.NewServer((&server{db: db}).routes())
	defer s.Close()
	c := newClient(t, s.URL)
	c.request("POST", "/api/register", credentials("reader", "123456"), 200)
	var wg sync.WaitGroup
	codes := make(chan int, 12)
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			req, _ := http.NewRequest("PUT", s.URL+"/api/state", bytes.NewBufferString(stateBody(0)))
			req.Header.Set("Content-Type", "application/json")
			res, err := c.http.Do(req)
			if err != nil {
				codes <- 0
				return
			}
			io.Copy(io.Discard, res.Body)
			res.Body.Close()
			codes <- res.StatusCode
		}()
	}
	wg.Wait()
	close(codes)
	success, conflict := 0, 0
	for code := range codes {
		switch code {
		case 200:
			success++
		case 409:
			conflict++
		default:
			t.Errorf("unexpected status %d", code)
		}
	}
	if success != 1 || conflict != 11 {
		t.Fatalf("lost update protection: %d successful, %d conflicts", success, conflict)
	}
}
