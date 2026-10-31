package main

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

//go:embed index.html account.js account.css
var assets embed.FS

type server struct {
	db       *sql.DB
	secure   bool
	basePath string
	attempts sync.Map
}
type user struct {
	ID       int64  `json:"id"`
	Username string `json:"username"`
	Role     string `json:"role"`
}
type attempt struct {
	count int
	until time.Time
}

var usernamePattern = regexp.MustCompile(`^[\p{L}\p{N}_-]{1,32}$`)

func openDB(path string) (*sql.DB, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	uriPath := filepath.ToSlash(abs)
	if !strings.HasPrefix(uriPath, "/") {
		uriPath = "/" + uriPath
	}
	u := url.URL{Scheme: "file", Path: uriPath}
	db, err := sql.Open("sqlite", u.String()+"?_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(8)
	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 password TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 created_at INTEGER NOT NULL DEFAULT (unixepoch()), last_login INTEGER);
 CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS sessions_user ON sessions(user_id);
 CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);
 CREATE TABLE IF NOT EXISTS states (user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE, data TEXT NOT NULL DEFAULT 'null', revision INTEGER NOT NULL DEFAULT 0);`)
	if err != nil {
		db.Close()
		return nil, err
	}
	var exists int
	err = db.QueryRow("SELECT count(*) FROM users WHERE username='admin'").Scan(&exists)
	if err == nil && exists == 0 {
		var hash []byte
		hash, err = bcrypt.GenerateFromPassword([]byte("110623"), bcrypt.DefaultCost)
		if err == nil {
			_, err = db.Exec("INSERT INTO users(username,password,role) VALUES('admin',?,'admin')", string(hash))
		}
	}
	if err != nil {
		db.Close()
		return nil, err
	}
	return db, nil
}
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	jsonReply(w, status, map[string]string{"error": msg})
}
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		fail(w, 415, "请使用 JSON 请求")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		fail(w, 400, "请求格式错误或数据超过 2MB")
		return false
	}
	if d.Decode(new(any)) != io.EOF {
		fail(w, 400, "请求格式错误")
		return false
	}
	return true
}
func tokenHash(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}
func (s *server) cookie(w http.ResponseWriter, token string, age int) {
	http.SetCookie(w, &http.Cookie{Name: "studyflow_session", Value: token, Path: s.basePath + "/", HttpOnly: true, Secure: s.secure, SameSite: http.SameSiteStrictMode, MaxAge: age})
}
func (s *server) current(r *http.Request) (user, error) {
	var u user
	c, err := r.Cookie("studyflow_session")
	if err != nil {
		return u, err
	}
	err = s.db.QueryRowContext(r.Context(), `SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token=? AND s.expires>unixepoch()`, tokenHash(c.Value)).Scan(&u.ID, &u.Username, &u.Role)
	return u, err
}
func (s *server) session(w http.ResponseWriter, r *http.Request, u user, passwordHash string) error {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return err
	}
	token := hex.EncodeToString(b)
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.Exec("DELETE FROM sessions WHERE expires<=unixepoch()"); err != nil {
		return err
	}
	if c, e := r.Cookie("studyflow_session"); e == nil {
		if _, err = tx.Exec("DELETE FROM sessions WHERE token=?", tokenHash(c.Value)); err != nil {
			return err
		}
	}
	result, err := tx.Exec("INSERT INTO sessions(token,user_id,expires) SELECT ?,id,? FROM users WHERE id=? AND password=?", tokenHash(token), time.Now().Add(7*24*time.Hour).Unix(), u.ID, passwordHash)
	if err != nil {
		return err
	}
	if n, _ := result.RowsAffected(); n != 1 {
		return errors.New("account changed during login; retry")
	}
	if _, err = tx.Exec("UPDATE users SET last_login=unixepoch() WHERE id=?", u.ID); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return err
	}
	s.cookie(w, token, 7*24*3600)
	return nil
}
func (s *server) limited(r *http.Request) bool {
	host, _, _ := net.SplitHostPort(r.RemoteAddr)
	now := time.Now()
	v, _ := s.attempts.LoadOrStore(host, &attempt{until: now.Add(10 * time.Minute)})
	// This lock is shared only by short rate-limit bookkeeping.
	limitMu.Lock()
	defer limitMu.Unlock()
	a := v.(*attempt)
	if now.After(a.until) {
		a.count = 0
		a.until = now.Add(10 * time.Minute)
	}
	a.count++
	return a.count > 40
}

var limitMu sync.Mutex

func (s *server) auth(w http.ResponseWriter, r *http.Request) {
	if s.limited(r) {
		fail(w, 429, "尝试过于频繁，请 10 分钟后重试")
		return
	}
	var in struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	in.Username = strings.TrimSpace(in.Username)
	if !usernamePattern.MatchString(in.Username) || len(in.Username) > 72 || len(in.Password) < 1 || len(in.Password) > 72 {
		fail(w, 400, "用户名需为 1–32 个文字、数字、下划线或短横线，密码最多 72 字节")
		return
	}
	var u user
	var hash string
	if r.URL.Path == "/api/register" {
		if len(in.Password) < 6 {
			fail(w, 400, "注册密码至少 6 个字节")
			return
		}
		h, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
		if err != nil {
			fail(w, 500, "无法创建账号")
			return
		}
		result, err := s.db.ExecContext(r.Context(), "INSERT INTO users(username,password) VALUES(?,?) ON CONFLICT(username) DO NOTHING", in.Username, string(h))
		if err != nil {
			s.internal(w, err)
			return
		}
		n, _ := result.RowsAffected()
		if n == 0 {
			fail(w, 409, "用户名已被使用")
			return
		}
		u.ID, _ = result.LastInsertId()
		u.Username = in.Username
		u.Role = "user"
		hash = string(h)
	} else {
		err := s.db.QueryRowContext(r.Context(), "SELECT id,username,role,password FROM users WHERE username=?", in.Username).Scan(&u.ID, &u.Username, &u.Role, &hash)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			s.internal(w, err)
			return
		}
		// Also perform a password hash comparison for unknown names.
		if hash == "" {
			hash = "$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy"
		}
		if bcrypt.CompareHashAndPassword([]byte(hash), []byte(in.Password)) != nil || err != nil {
			fail(w, 401, "用户名或密码错误")
			return
		}
	}
	if err := s.session(w, r, u, hash); err != nil {
		s.internal(w, err)
		return
	}
	jsonReply(w, 200, u)
}
func (s *server) internal(w http.ResponseWriter, err error) {
	log.Printf("request failed: %v", err)
	fail(w, 500, "服务器暂时无法完成操作，请重试")
}
func (s *server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		var one int
		if err := s.db.QueryRowContext(r.Context(), "SELECT 1").Scan(&one); err != nil {
			fail(w, http.StatusServiceUnavailable, "数据库不可用")
			return
		}
		jsonReply(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("POST /api/register", s.auth)
	mux.HandleFunc("POST /api/login", s.auth)
	mux.HandleFunc("GET /api/me", func(w http.ResponseWriter, r *http.Request) {
		u, err := s.current(r)
		if err != nil {
			fail(w, 401, "请先登录")
			return
		}
		jsonReply(w, 200, u)
	})
	mux.HandleFunc("POST /api/logout", func(w http.ResponseWriter, r *http.Request) {
		if c, e := r.Cookie("studyflow_session"); e == nil {
			if _, err := s.db.ExecContext(r.Context(), "DELETE FROM sessions WHERE token=?", tokenHash(c.Value)); err != nil {
				s.internal(w, err)
				return
			}
		}
		s.cookie(w, "", -1)
		jsonReply(w, 200, map[string]bool{"ok": true})
	})
	mux.HandleFunc("GET /api/state", s.withUser(s.getState, false))
	mux.HandleFunc("PUT /api/state", s.withUser(s.putState, false))
	mux.HandleFunc("POST /api/password", s.withUser(s.password, false))
	mux.HandleFunc("GET /api/admin/users", s.withUser(s.users, true))
	mux.HandleFunc("DELETE /api/admin/users/{id}", s.withUser(s.manageUser, true))
	mux.HandleFunc("POST /api/admin/users/{id}/reset-password", s.withUser(s.manageUser, true))
	mux.HandleFunc("/api/", func(w http.ResponseWriter, r *http.Request) { fail(w, 404, "接口不存在") })
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" && r.Method != "HEAD" {
			w.Header().Set("Allow", "GET, HEAD")
			fail(w, 405, "请求方法不支持")
			return
		}
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" {
			path = "index.html"
		}
		if path != "index.html" && path != "account.js" && path != "account.css" {
			http.NotFound(w, r)
			return
		}
		data, _ := assets.ReadFile(path)
		types := map[string]string{"index.html": "text/html; charset=utf-8", "account.js": "text/javascript; charset=utf-8", "account.css": "text/css; charset=utf-8"}
		w.Header().Set("Content-Type", types[path])
		w.Write(data)
	})
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method != "GET" && r.Method != "HEAD" {
			if origin := r.Header.Get("Origin"); origin != "" {
				u, err := url.Parse(origin)
				if err != nil || u.Host != r.Host || (u.Scheme != "http" && u.Scheme != "https") {
					fail(w, 403, "不允许跨站请求")
					return
				}
			}
			if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
				fail(w, 403, "不允许跨站请求")
				return
			}
		}
		mux.ServeHTTP(w, r)
	})
}
func (s *server) withUser(next func(http.ResponseWriter, *http.Request, user), admin bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		u, err := s.current(r)
		if err != nil {
			fail(w, 401, "登录已失效，请重新登录")
			return
		}
		if admin && u.Role != "admin" {
			fail(w, 403, "仅管理员可操作")
			return
		}
		next(w, r, u)
	}
}
func (s *server) getState(w http.ResponseWriter, r *http.Request, u user) {
	var data string
	var rev int64
	err := s.db.QueryRowContext(r.Context(), "SELECT data,revision FROM states WHERE user_id=?", u.ID).Scan(&data, &rev)
	if errors.Is(err, sql.ErrNoRows) {
		data = "null"
	} else if err != nil {
		s.internal(w, err)
		return
	}
	jsonReply(w, 200, map[string]any{"data": json.RawMessage(data), "revision": rev})
}
func (s *server) putState(w http.ResponseWriter, r *http.Request, u user) {
	var in struct {
		Data     json.RawMessage `json:"data"`
		Revision int64           `json:"revision"`
	}
	if !decode(w, r, &in) {
		return
	}
	if !validState(in.Data) || in.Revision < 0 {
		fail(w, 400, "学习数据格式不正确")
		return
	}
	result, err := s.db.ExecContext(r.Context(), `INSERT INTO states(user_id,data,revision) SELECT ?,?,1 WHERE ?=0 OR EXISTS(SELECT 1 FROM states WHERE user_id=?) ON CONFLICT(user_id) DO UPDATE SET data=excluded.data,revision=states.revision+1 WHERE states.revision=?`, u.ID, string(in.Data), in.Revision, u.ID, in.Revision)
	if err != nil {
		s.internal(w, err)
		return
	}
	n, _ := result.RowsAffected()
	if n == 0 {
		fail(w, 409, "其他窗口已修改数据，请先导出当前数据，再刷新页面")
		return
	}
	jsonReply(w, 200, map[string]int64{"revision": in.Revision + 1})
}
func validState(data []byte) bool {
	var v struct {
		Tasks       []json.RawMessage  `json:"tasks"`
		Blocks      []json.RawMessage  `json:"blocks"`
		FocusLog    map[string]float64 `json:"focusLog"`
		FocusByTask map[string]float64 `json:"focusByTask"`
		Timer       *struct {
			Mode         string  `json:"mode"`
			FocusMin     float64 `json:"focusMin"`
			BreakMin     float64 `json:"breakMin"`
			RemainingSec float64 `json:"remainingSec"`
			Running      bool    `json:"running"`
			EndAt        *int64  `json:"endAt"`
			TaskID       string  `json:"taskId"`
		} `json:"timer"`
	}
	if json.Unmarshal(data, &v) != nil || v.Tasks == nil || v.Blocks == nil || v.FocusLog == nil || v.FocusByTask == nil || v.Timer == nil {
		return false
	}
	t := v.Timer
	if (t.Mode != "focus" && t.Mode != "break") || t.FocusMin < 1 || t.FocusMin > 180 || t.BreakMin < 1 || t.BreakMin > 60 || t.RemainingSec < 0 || t.RemainingSec > 10800 {
		return false
	}
	for _, raw := range v.Tasks {
		var task struct {
			ID          string `json:"id"`
			Title       string `json:"title"`
			Notes       string `json:"notes"`
			Deadline    string `json:"deadline"`
			Estimate    int    `json:"estimate"`
			Important   bool   `json:"important"`
			Urgent      bool   `json:"urgent"`
			Completed   bool   `json:"completed"`
			CompletedAt *int64 `json:"completedAt"`
			CreatedAt   int64  `json:"createdAt"`
			Sample      bool   `json:"sample"`
			Subtasks    []struct {
				ID    string `json:"id"`
				Title string `json:"title"`
				Done  bool   `json:"done"`
			} `json:"subtasks"`
		}
		if json.Unmarshal(raw, &task) != nil || task.ID == "" || task.Title == "" {
			return false
		}
		if task.Estimate < 0 || task.Estimate > 1440 || !validDate(task.Deadline, true) {
			return false
		}
	}
	for _, raw := range v.Blocks {
		var block struct {
			ID     string `json:"id"`
			TaskID string `json:"taskId"`
			Date   string `json:"date"`
			Start  string `json:"start"`
			End    string `json:"end"`
		}
		if json.Unmarshal(raw, &block) != nil || block.ID == "" || block.TaskID == "" || block.Date == "" || block.Start == "" || block.End == "" {
			return false
		}
		if !validDate(block.Date, false) {
			return false
		}
		start, err := time.Parse("15:04", block.Start)
		if err != nil {
			return false
		}
		end, err := time.Parse("15:04", block.End)
		if err != nil || !end.After(start) {
			return false
		}
	}
	return true
}
func validDate(value string, optional bool) bool {
	if value == "" && optional {
		return true
	}
	_, err := time.Parse("2006-01-02", value)
	return err == nil
}
func (s *server) password(w http.ResponseWriter, r *http.Request, u user) {
	var in struct {
		Current  string `json:"current"`
		Password string `json:"password"`
	}
	if !decode(w, r, &in) {
		return
	}
	if len(in.Password) < 6 || len(in.Password) > 72 {
		fail(w, 400, "新密码需为 6–72 个字节")
		return
	}
	var old string
	if err := s.db.QueryRowContext(r.Context(), "SELECT password FROM users WHERE id=?", u.ID).Scan(&old); err != nil {
		s.internal(w, err)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(old), []byte(in.Current)) != nil {
		fail(w, 400, "当前密码错误")
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(in.Password), bcrypt.DefaultCost)
	if err != nil {
		s.internal(w, err)
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer tx.Rollback()
	result, err := tx.Exec("UPDATE users SET password=? WHERE id=? AND password=?", string(hash), u.ID, old)
	if err != nil {
		s.internal(w, err)
		return
	}
	n, _ := result.RowsAffected()
	if n != 1 {
		fail(w, 409, "密码已发生变化，请重新登录")
		return
	}
	if _, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", u.ID); err != nil {
		s.internal(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		s.internal(w, err)
		return
	}
	s.cookie(w, "", -1)
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (s *server) users(w http.ResponseWriter, r *http.Request, u user) {
	rows, err := s.db.QueryContext(r.Context(), `SELECT u.id,u.username,u.role,u.created_at,coalesce(u.last_login,0),(SELECT count(*) FROM sessions s WHERE s.user_id=u.id AND s.expires>unixepoch()) FROM users u ORDER BY u.id`)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer rows.Close()
	list := []any{}
	for rows.Next() {
		var v user
		var created, last, sessions int64
		if err = rows.Scan(&v.ID, &v.Username, &v.Role, &created, &last, &sessions); err != nil {
			s.internal(w, err)
			return
		}
		list = append(list, map[string]any{"id": v.ID, "username": v.Username, "role": v.Role, "createdAt": created, "lastLogin": last, "sessions": sessions})
	}
	if err = rows.Err(); err != nil {
		s.internal(w, err)
		return
	}
	jsonReply(w, 200, list)
}
func (s *server) manageUser(w http.ResponseWriter, r *http.Request, u user) {
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		fail(w, 400, "用户 ID 无效")
		return
	}
	var name, role string
	if err = s.db.QueryRowContext(r.Context(), "SELECT username,role FROM users WHERE id=?", id).Scan(&name, &role); errors.Is(err, sql.ErrNoRows) {
		fail(w, 404, "用户不存在")
		return
	} else if err != nil {
		s.internal(w, err)
		return
	}
	if role == "admin" {
		fail(w, 403, "管理员账号不能删除或重置，请使用修改密码")
		return
	}
	tx, err := s.db.BeginTx(r.Context(), nil)
	if err != nil {
		s.internal(w, err)
		return
	}
	defer tx.Rollback()
	if r.Method == "DELETE" {
		_, err = tx.Exec("DELETE FROM users WHERE id=? AND role='user'", id)
	} else {
		var hash []byte
		hash, err = bcrypt.GenerateFromPassword([]byte(name), bcrypt.DefaultCost)
		if err == nil {
			_, err = tx.Exec("UPDATE users SET password=? WHERE id=? AND role='user'", string(hash), id)
		}
		if err == nil {
			_, err = tx.Exec("DELETE FROM sessions WHERE user_id=?", id)
		}
	}
	if err != nil {
		s.internal(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		s.internal(w, err)
		return
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func main() {
	path := os.Getenv("STUDYFLOW_DB")
	if path == "" {
		path = "data/studyflow.db"
	}
	db, err := openDB(path)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()
	basePath := strings.TrimRight(os.Getenv("STUDYFLOW_BASE_PATH"), "/")
	if !regexp.MustCompile(`^(/[a-zA-Z0-9_-]+)*$`).MatchString(basePath) {
		log.Fatal("STUDYFLOW_BASE_PATH must be a URL path such as /study-flow")
	}
	s := &server{db: db, secure: os.Getenv("STUDYFLOW_SECURE_COOKIE") == "1", basePath: basePath}
	addr := os.Getenv("STUDYFLOW_ADDR")
	if addr == "" {
		addr = "127.0.0.1:8080"
	}
	srv := &http.Server{Addr: addr, Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 1 << 16}
	stop, cancel := signal.NotifyContext(context.Background(), os.Interrupt)
	defer cancel()
	go func() {
		<-stop.Done()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(ctx)
	}()
	fmt.Printf("StudyFlow: http://%s\n", addr)
	if err = srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
