#!/usr/bin/env python3
"""Máy chủ cho trang Warhammer 40k: tài khoản lưu trong SQLite.
Chạy:  python3 server.py   (mặc định http://localhost:8000, đổi cổng: PORT=9000 python3 server.py)
Chỉ dùng thư viện chuẩn của Python 3, không cần cài thêm gì."""
import hashlib, hmac, json, mimetypes, os, re, secrets, sqlite3, time
from datetime import datetime
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

BASE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(BASE, "users.db")
PORT = int(os.environ.get("PORT", "8000"))
TTL = 7 * 86400
BLOCKED = {"server.py", "users.db", "gate.html", "site.html"}
NAME_RE = re.compile(r"^[a-z0-9_.-]{3,32}$")


def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c


def hp(pw, salt):
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), bytes.fromhex(salt), 200000).hex()


def now():
    return datetime.now().strftime("%Y-%m-%d %H:%M")


def add_user(c, name, pw, role="user"):
    salt = secrets.token_hex(16)
    c.execute("INSERT INTO users(username,salt,hash,role,created_at) VALUES(?,?,?,?,?)",
              (name, salt, hp(pw, salt), role, now()))


def init():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
          id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL,
          salt TEXT NOT NULL, hash TEXT NOT NULL, role TEXT NOT NULL DEFAULT 'user',
          created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(
          token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
          expires REAL NOT NULL);""")
        if not c.execute("SELECT 1 FROM users WHERE username='admin'").fetchone():
            add_user(c, "admin", "admin", "admin")
            print("Đã tạo tài khoản admin / mật khẩu: admin  -> hãy đổi mật khẩu sau khi đăng nhập!")
        a = c.execute("SELECT salt,hash FROM users WHERE username='admin'").fetchone()
        if a and hmac.compare_digest(a["hash"], hp("admin", a["salt"])):
            print("CẢNH BÁO: admin vẫn dùng mật khẩu mặc định 'admin'.")


class H(BaseHTTPRequestHandler):
    server_version = "wh40k"

    def log_message(self, *a):
        pass

    # ---------- tiện ích ----------
    def send(self, code, body, ctype="application/json; charset=utf-8", cookie=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body, ensure_ascii=False).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        self.wfile.write(body)

    def err(self, code, msg):
        self.send(code, {"error": msg})

    def token(self):
        c = cookies.SimpleCookie(self.headers.get("Cookie", ""))
        return c["sid"].value if "sid" in c else None

    def user(self):
        t = self.token()
        if not t:
            return None
        with db() as c:
            r = c.execute("SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id "
                          "WHERE s.token=? AND s.expires>?", (t, time.time())).fetchone()
        return dict(r) if r else None

    def login_cookie(self, c, uid):
        t = secrets.token_urlsafe(32)
        c.execute("DELETE FROM sessions WHERE expires<?", (time.time(),))
        c.execute("INSERT INTO sessions(token,user_id,expires) VALUES(?,?,?)", (t, uid, time.time() + TTL))
        return f"sid={t}; HttpOnly; SameSite=Lax; Path=/; Max-Age={TTL}"

    def body(self):
        if "application/json" not in self.headers.get("Content-Type", ""):
            return None
        n = int(self.headers.get("Content-Length") or 0)
        if n > 10000:
            return None
        try:
            d = json.loads(self.rfile.read(n) or b"{}")
            return d if isinstance(d, dict) else None
        except ValueError:
            return None

    # ---------- GET ----------
    def do_GET(self):
        path = unquote(urlsplit(self.path).path)
        u = self.user()
        if path == "/api/me":
            if not u:
                return self.err(401, "Chưa đăng nhập.")
            return self.send(200, {"username": u["username"], "role": u["role"]})
        if path == "/api/users":
            if not u or u["role"] != "admin":
                return self.err(403, "Không có quyền.")
            with db() as c:
                rows = c.execute("SELECT username,role,created_at FROM users ORDER BY id").fetchall()
            return self.send(200, {"users": [dict(r) for r in rows]})
        if path in ("/", "/index.html"):
            f = "site.html" if u else "gate.html"
            with open(os.path.join(BASE, f), "rb") as fh:
                return self.send(200, fh.read(), "text/html; charset=utf-8")
        # tệp tĩnh khác (ảnh, trang con...) chỉ cho người đã đăng nhập
        if not u:
            return self.err(401, "Cần đăng nhập.")
        full = os.path.realpath(os.path.join(BASE, path.lstrip("/")))
        name = os.path.basename(full)
        if (not full.startswith(BASE + os.sep) or name in BLOCKED or name.startswith(".")
                or name.endswith((".db", ".py")) or not os.path.isfile(full)):
            return self.err(404, "Không tìm thấy.")
        with open(full, "rb") as fh:
            self.send(200, fh.read(), mimetypes.guess_type(full)[0] or "application/octet-stream")

    # ---------- POST ----------
    def do_POST(self):
        path = urlsplit(self.path).path
        d = self.body()
        if d is None:
            return self.err(400, "Yêu cầu không hợp lệ.")
        u = self.user()
        if path == "/api/register":
            name = str(d.get("username", "")).strip().lower()
            pw = str(d.get("password", ""))
            if not NAME_RE.match(name):
                return self.err(400, "Tên đăng nhập 3–32 ký tự: chữ thường, số, _ . -")
            if not 6 <= len(pw) <= 128:
                return self.err(400, "Mật khẩu cần từ 6 đến 128 ký tự.")
            with db() as c:
                try:
                    add_user(c, name, pw)
                except sqlite3.IntegrityError:
                    return self.err(409, "Tên đăng nhập đã tồn tại.")
                uid = c.execute("SELECT id FROM users WHERE username=?", (name,)).fetchone()["id"]
                ck = self.login_cookie(c, uid)
            return self.send(200, {"ok": True}, cookie=ck)
        if path == "/api/login":
            name = str(d.get("username", "")).strip().lower()
            pw = str(d.get("password", ""))
            with db() as c:
                r = c.execute("SELECT id,salt,hash FROM users WHERE username=?", (name,)).fetchone()
                salt = r["salt"] if r else "00" * 16
                ok = hmac.compare_digest(hp(pw, salt), r["hash"] if r else "x") if r else False
                if not ok:
                    time.sleep(0.5)
                    return self.err(401, "Sai tên đăng nhập hoặc mật khẩu.")
                ck = self.login_cookie(c, r["id"])
            return self.send(200, {"ok": True}, cookie=ck)
        if path == "/api/logout":
            t = self.token()
            if t:
                with db() as c:
                    c.execute("DELETE FROM sessions WHERE token=?", (t,))
            return self.send(200, {"ok": True}, cookie="sid=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        if not u:
            return self.err(401, "Chưa đăng nhập.")
        if path == "/api/password":
            old, new = str(d.get("old", "")), str(d.get("new", ""))
            if not 6 <= len(new) <= 128:
                return self.err(400, "Mật khẩu mới cần từ 6 đến 128 ký tự.")
            with db() as c:
                r = c.execute("SELECT salt,hash FROM users WHERE id=?", (u["id"],)).fetchone()
                if not hmac.compare_digest(hp(old, r["salt"]), r["hash"]):
                    return self.err(403, "Mật khẩu hiện tại không đúng.")
                salt = secrets.token_hex(16)
                c.execute("UPDATE users SET salt=?,hash=? WHERE id=?", (salt, hp(new, salt), u["id"]))
            return self.send(200, {"ok": True})
        if path == "/api/users/delete":
            if u["role"] != "admin":
                return self.err(403, "Không có quyền.")
            name = str(d.get("username", "")).strip().lower()
            if name == "admin":
                return self.err(400, "Không thể xóa tài khoản admin.")
            with db() as c:
                c.execute("DELETE FROM users WHERE username=?", (name,))
            return self.send(200, {"ok": True})
        self.err(404, "Không tìm thấy.")


if __name__ == "__main__":
    init()
    print(f"Đang chạy tại http://localhost:{PORT}  (Ctrl+C để dừng)")
    ThreadingHTTPServer(("0.0.0.0", PORT), H).serve_forever()
