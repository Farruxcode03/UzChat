import hashlib
import hmac
import json
import os
import random
import re
import sqlite3
import threading
import time
import urllib.request
import uuid
from flask import Flask, jsonify, request, session

app = Flask(__name__, template_folder=".", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "uzchat-secret-key-2026")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8595083453:AAEp_6M7b3rf47cgFqrRtF6T4T_mq5uFdh4")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "FarruxCodeWorkbot")
DB_PATH = os.environ.get("DB_PATH", "uzchat.db")

_DB_LOCK = threading.Lock()
_TG_LOCK = threading.Lock()
_TG_STARTED = False
LAST_UPDATE_ID = 0


def get_db():
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _DB_LOCK:
        conn = get_db()
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                phone_digits TEXT PRIMARY KEY,
                id TEXT NOT NULL,
                name TEXT NOT NULL,
                username TEXT UNIQUE NOT NULL,
                phone TEXT NOT NULL,
                password_hash TEXT NOT NULL,
                created_at REAL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS auth_tokens (
                token TEXT PRIMARY KEY,
                mode TEXT NOT NULL,
                phone_digits TEXT NOT NULL,
                phone TEXT DEFAULT '',
                name TEXT DEFAULT '',
                username TEXT DEFAULT '',
                code TEXT NOT NULL,
                phone_matched INTEGER DEFAULT 0,
                verified INTEGER DEFAULT 0,
                tg_chat_id TEXT DEFAULT '',
                expires REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS meta_state (
                k TEXT PRIMARY KEY,
                v TEXT NOT NULL
            )
        """)
        conn.commit()
        conn.close()


init_db()


def load_last_update_id() -> int:
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT v FROM meta_state WHERE k = 'last_update_id'").fetchone()
        conn.close()
        return int(row["v"]) if row and str(row["v"]).isdigit() else 0


def save_last_update_id(upd_id: int):
    with _DB_LOCK:
        conn = get_db()
        conn.execute(
            "INSERT INTO meta_state(k, v) VALUES('last_update_id', ?) ON CONFLICT(k) DO UPDATE SET v = excluded.v",
            (str(upd_id),),
        )
        conn.commit()
        conn.close()


LAST_UPDATE_ID = load_last_update_id()


def norm_phone(p: str) -> str:
    return re.sub(r"\D", "", p or "")


def norm_username(u: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", (u or "").strip().lstrip("@").lower())


def hash_password(raw: str) -> str:
    return hmac.new(app.secret_key.encode("utf-8"), (raw or "").encode("utf-8"), hashlib.sha256).hexdigest()


def get_user_by_phone_digits(digits: str):
    if not digits:
        return None
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE phone_digits = ?", (digits,)).fetchone()
        conn.close()
    return dict(row) if row else None


def get_user_by_username(uname: str):
    u_clean = norm_username(uname)
    if not u_clean:
        return None
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (u_clean,)).fetchone()
        conn.close()
    return dict(row) if row else None


def save_auth_token(token: str, rec: dict):
    with _DB_LOCK:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO auth_tokens(
                token, mode, phone_digits, phone, name, username,
                code, phone_matched, verified, tg_chat_id, expires
            ) VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(token) DO UPDATE SET
                mode = excluded.mode,
                phone_digits = excluded.phone_digits,
                phone = excluded.phone,
                name = excluded.name,
                username = excluded.username,
                code = excluded.code,
                phone_matched = excluded.phone_matched,
                verified = excluded.verified,
                tg_chat_id = excluded.tg_chat_id,
                expires = excluded.expires
            """,
            (
                token,
                rec.get("mode", "signup"),
                rec.get("phone_digits", ""),
                rec.get("phone", ""),
                rec.get("name", ""),
                rec.get("username", ""),
                rec.get("code", ""),
                1 if rec.get("phone_matched") else 0,
                1 if rec.get("verified") else 0,
                str(rec.get("tg_chat_id") or ""),
                float(rec.get("expires") or 0),
            ),
        )
        conn.commit()
        conn.close()


def get_auth_token(token: str):
    if not token:
        return None
    now = time.time()
    with _DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM auth_tokens WHERE expires < ?", (now,))
        row = conn.execute("SELECT * FROM auth_tokens WHERE token = ?", (token,)).fetchone()
        conn.commit()
        conn.close()
    if not row:
        return None
    return {
        "token": row["token"],
        "mode": row["mode"],
        "phone_digits": row["phone_digits"],
        "phone": row["phone"],
        "name": row["name"],
        "username": row["username"],
        "code": row["code"],
        "phone_matched": bool(row["phone_matched"]),
        "verified": bool(row["verified"]),
        "tg_chat_id": row["tg_chat_id"] or None,
        "expires": float(row["expires"]),
    }


def list_active_auth_tokens():
    now = time.time()
    with _DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM auth_tokens WHERE expires < ?", (now,))
        rows = conn.execute("SELECT * FROM auth_tokens ORDER BY expires ASC").fetchall()
        conn.commit()
        conn.close()
    return [
        {
            "token": r["token"],
            "mode": r["mode"],
            "phone_digits": r["phone_digits"],
            "phone": r["phone"],
            "name": r["name"],
            "username": r["username"],
            "code": r["code"],
            "phone_matched": bool(r["phone_matched"]),
            "verified": bool(r["verified"]),
            "tg_chat_id": r["tg_chat_id"] or None,
            "expires": float(r["expires"]),
        }
        for r in rows
    ]


def tg_api(method: str, payload: dict | None = None):
    if not BOT_TOKEN:
        return None
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/{method}"
    try:
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
        else:
            req = urllib.request.Request(url)
        with urllib.request.urlopen(req, timeout=8) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[TG_API_ERR] {method}: {e}")
        return None


def sync_telegram_updates():
    global LAST_UPDATE_ID
    with _TG_LOCK:
        params = {"timeout": 0, "allowed_updates": ["message"]}
        if LAST_UPDATE_ID:
            params["offset"] = LAST_UPDATE_ID + 1

        res = tg_api("getUpdates", params)
        if not res or not res.get("ok"):
            return

        now = time.time()
        max_seen = LAST_UPDATE_ID
        active_tokens = list_active_auth_tokens()

        for upd in res.get("result", []):
            upd_id = int(upd.get("update_id", 0) or 0)
            if upd_id > max_seen:
                max_seen = upd_id

            msg = upd.get("message") or {}
            chat_id = (msg.get("chat") or {}).get("id")
            txt = (msg.get("text") or "").strip()
            contact = msg.get("contact") or {}

            if not chat_id:
                continue

            if txt.startswith("/start"):
                parts = txt.split(maxsplit=1)
                param = parts[1].strip() if len(parts) > 1 else ""
                matched_rec = None
                for rec in active_tokens:
                    if now <= rec.get("expires", 0) and param and rec["token"].startswith(param):
                        matched_rec = rec
                        break
                if not matched_rec:
                    for rec in reversed(active_tokens):
                        if now <= rec.get("expires", 0) and not rec.get("verified"):
                            matched_rec = rec
                            break
                if matched_rec:
                    matched_rec["tg_chat_id"] = str(chat_id)
                    save_auth_token(matched_rec["token"], matched_rec)

                tg_api("sendMessage", {
                    "chat_id": chat_id,
                    "text": "Tasdiqlash kodini olish uchun pastdagi tugma orqali telefon raqamingizni yuboring:",
                    "reply_markup": {
                        "keyboard": [[{"text": "📱 Telefon raqamni yuborish", "request_contact": True}]],
                        "resize_keyboard": True,
                        "one_time_keyboard": True,
                    },
                })
                continue

            if contact.get("phone_number"):
                tg_digits = norm_phone(contact["phone_number"])
                sender_id = (msg.get("from") or {}).get("id")
                contact_user_id = contact.get("user_id")
                if sender_id and contact_user_id and sender_id != contact_user_id:
                    tg_api("sendMessage", {
                        "chat_id": chat_id,
                        "text": "❌ Faqat o'zingizning Telegram telefon raqamingizni yuboring.",
                    })
                    continue

                matched = False
                for rec in active_tokens:
                    if now > rec.get("expires", 0):
                        continue
                    if rec.get("phone_digits") == tg_digits:
                        matched = True
                        rec["tg_chat_id"] = str(chat_id)
                        rec["phone_matched"] = True
                        rec["verified"] = True
                        save_auth_token(rec["token"], rec)
                        tg_api("sendMessage", {
                            "chat_id": chat_id,
                            "text": f"✅ Tasdiqlash kodi: <b>{rec['code']}</b>\nKod saytga ham avtomatik yuborildi.",
                            "parse_mode": "HTML",
                            "reply_markup": {"remove_keyboard": True},
                        })

                if not matched:
                    tg_api("sendMessage", {
                        "chat_id": chat_id,
                        "text": "❌ Yuborilgan telefon raqam saytda kiritilgan raqam bilan mos kelmadi.",
                    })

        if max_seen > LAST_UPDATE_ID:
            LAST_UPDATE_ID = max_seen
            save_last_update_id(LAST_UPDATE_ID)


def _tg_worker():
    tg_api("deleteWebhook", {"drop_pending_updates": False})
    while True:
        try:
            sync_telegram_updates()
        except Exception as e:
            print(f"[TG_WORKER_ERR] {e}")
        time.sleep(2.0)


def ensure_tg_worker():
    global _TG_STARTED
    if _TG_STARTED:
        return
    _TG_STARTED = True
    threading.Thread(target=_tg_worker, daemon=True).start()


ensure_tg_worker()


@app.route("/")
def index():
    ensure_tg_worker()
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "index.html")
    with open(path, "r", encoding="utf-8") as f:
        html = f.read()
    return html.replace("{{ bot_username or 'FarruxCodeWorkbot' }}", BOT_USERNAME).replace("{{ bot_username }}", BOT_USERNAME)


@app.post("/api/signup/start")
def signup_start():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    username = norm_username(data.get("username"))
    phone = (data.get("phone") or "").strip()
    digits = norm_phone(phone)

    if not name or not username or len(digits) < 7:
        return jsonify({"ok": False, "error": "Ism, @username (harf/raqam) va telefon raqamni to'g'ri kiriting."}), 400

    if get_user_by_phone_digits(digits):
        return jsonify({"ok": False, "error": "Bu telefon raqam bilan profil allaqachon ochilgan."}), 400

    if get_user_by_username(username):
        return jsonify({"ok": False, "error": f"@{username} band."}), 400

    code = f"{random.randint(100000, 999999)}"
    token = str(uuid.uuid4())
    save_auth_token(token, {
        "mode": "signup",
        "phone_digits": digits,
        "phone": phone,
        "name": name,
        "username": username,
        "code": code,
        "phone_matched": False,
        "verified": False,
        "tg_chat_id": None,
        "expires": time.time() + 600,
    })

    return jsonify({
        "ok": True,
        "token": token,
        "bot_url": f"https://t.me/{BOT_USERNAME}?start={token[:8]}",
    })


@app.get("/api/signup/status/<token>")
def signup_status(token: str):
    sync_telegram_updates()
    rec = get_auth_token(token)
    if not rec:
        return jsonify({"ok": False, "error": "Muddati o'tgan."}), 404
    ok_ver = bool(rec.get("verified") and rec.get("phone_matched"))
    return jsonify({"ok": True, "verified": ok_ver, "code": rec.get("code") if ok_ver else None})


@app.post("/api/signup/complete")
def signup_complete():
    sync_telegram_updates()
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    code = (data.get("code") or "").strip()
    p1 = data.get("password") or ""
    p2 = data.get("confirm_password") or ""

    rec = get_auth_token(token)
    if not rec:
        return jsonify({"ok": False, "error": "Sessiya topilmadi yoki muddati o'tgan."}), 400
    if not rec.get("verified") or not rec.get("phone_matched"):
        return jsonify({"ok": False, "error": "Avval Telegram botda telefon raqamingizni yuboring."}), 400
    if code != rec["code"]:
        return jsonify({"ok": False, "error": "Kod noto'g'ri."}), 400
    if len(p1) < 4 or p1 != p2:
        return jsonify({"ok": False, "error": "Parol kamida 4 belgi va bir xil bo'lishi kerak."}), 400

    digits = rec["phone_digits"]
    user = {
        "id": str(uuid.uuid4()),
        "name": rec["name"],
        "username": rec["username"],
        "phone": rec["phone"],
    }
    with _DB_LOCK:
        conn = get_db()
        conn.execute(
            "INSERT INTO users(phone_digits, id, name, username, phone, password_hash, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (digits, user["id"], user["name"], user["username"], user["phone"], hash_password(p1), time.time()),
        )
        conn.commit()
        conn.close()

    session["user_phone"] = digits
    return jsonify({"ok": True, "user": user})


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    digits = norm_phone(data.get("phone"))
    password = data.get("password") or ""
    row = get_user_by_phone_digits(digits)
    if not row or not hmac.compare_digest(row["password_hash"], hash_password(password)):
        return jsonify({"ok": False, "error": "Telefon raqam yoki parol noto'g'ri."}), 401
    session["user_phone"] = digits
    return jsonify({
        "ok": True,
        "user": {"id": row["id"], "name": row["name"], "username": row["username"], "phone": row["phone"]},
    })


@app.post("/api/logout")
def logout():
    session.pop("user_phone", None)
    return jsonify({"ok": True})


if __name__ == "__main__":
    ensure_tg_worker()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=True)
