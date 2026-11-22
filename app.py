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
from flask import Flask, jsonify, render_template, request, send_from_directory, session

app = Flask(__name__, template_folder=".", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "uzchat-secret-key")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "8595083453:AAEp_6M7b3rf47cgFqrRtF6T4T_mq5uFdh4")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "FarruxCodeWorkbot")
UPLOAD_DIR = os.path.join(app.static_folder, "uploads")
DB_PATH = os.environ.get("DB_PATH", "uzchat.db")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(app.template_folder, exist_ok=True)

SPAM_THRESHOLD = 3
SPAM_WINDOW_SEC = 86400
SPAM_BLOCK_SEC = 86400
ONLINE_WINDOW_SEC = 20
_DB_LOCK = threading.Lock()
_TG_LOCK = threading.Lock()
_TG_BG_STARTED = False
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
                bio TEXT DEFAULT '',
                last_seen REAL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS chats (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                username TEXT DEFAULT '',
                kind TEXT NOT NULL,
                admin TEXT NOT NULL,
                members_json TEXT NOT NULL,
                created_at REAL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS secret_chats (
                id TEXT PRIMARY KEY,
                user_a TEXT NOT NULL,
                user_b TEXT NOT NULL,
                auto_destruct_sec INTEGER DEFAULT 30,
                created_at REAL DEFAULT 0
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id TEXT PRIMARY KEY,
                sender TEXT NOT NULL,
                sender_username TEXT NOT NULL,
                chat_id TEXT NOT NULL,
                text TEXT DEFAULT '',
                reply_to TEXT,
                media_url TEXT,
                media_type TEXT,
                time_str TEXT NOT NULL,
                ts REAL NOT NULL,
                expire_at REAL DEFAULT 0,
                edited INTEGER DEFAULT 0
            )
        """)
        cols = [r["name"] for r in cur.execute("PRAGMA table_info(messages)").fetchall()]
        if "expire_at" not in cols:
            cur.execute("ALTER TABLE messages ADD COLUMN expire_at REAL DEFAULT 0")

        cur.execute("""
            CREATE TABLE IF NOT EXISTS spam_reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                target_lower TEXT NOT NULL,
                ts REAL NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS spam_blocks (
                user_lower TEXT PRIMARY KEY,
                blocked_until REAL NOT NULL
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
    salt = app.secret_key.encode("utf-8")
    return hmac.new(salt, (raw or "").encode("utf-8"), hashlib.sha256).hexdigest()


def is_online(last_seen: float) -> bool:
    return (time.time() - float(last_seen or 0)) <= ONLINE_WINDOW_SEC


def row_to_user(row) -> dict:
    return {
        "id": row["id"],
        "name": row["name"],
        "username": row["username"],
        "phone": row["phone"],
        "bio": row["bio"] or "",
        "last_seen": float(row["last_seen"] or 0),
        "online": is_online(float(row["last_seen"] or 0)),
    }


def public_user(user: dict) -> dict:
    ls = float(user.get("last_seen", 0) or 0)
    return {
        "id": user["id"],
        "name": user["name"],
        "username": user["username"],
        "phone": user["phone"],
        "bio": user.get("bio", ""),
        "online": is_online(ls),
        "last_seen": ls,
    }


def get_user_by_phone_digits(digits: str):
    if not digits:
        return None
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE phone_digits = ?", (digits,)).fetchone()
        conn.close()
    return row_to_user(row) if row else None


def get_user_by_username(uname: str):
    u_clean = norm_username(uname)
    if not u_clean:
        return None
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE username = ?", (u_clean,)).fetchone()
        conn.close()
    return row_to_user(row) if row else None


def get_current_user():
    digits = session.get("user_phone")
    if not digits:
        return None
    now = time.time()
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE phone_digits = ?", (digits,)).fetchone()
        if not row:
            conn.close()
            return None
        conn.execute("UPDATE users SET last_seen = ? WHERE phone_digits = ?", (now, digits))
        conn.commit()
        conn.close()
    u = row_to_user(row)
    u["last_seen"] = now
    u["online"] = True
    return u


def find_user_by_phone_and_password(phone_or_ident: str, password: str):
    digits = norm_phone(phone_or_ident)
    if not digits:
        return None
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM users WHERE phone_digits = ?", (digits,)).fetchone()
        conn.close()
    if not row:
        return None
    if not password or not hmac.compare_digest(row["password_hash"] or "", hash_password(password)):
        return None
    return row_to_user(row)


def get_spam_status(user_name: str) -> dict:
    low = (user_name or "").strip().lower()
    now = time.time()
    with _DB_LOCK:
        conn = get_db()
        blk = conn.execute("SELECT blocked_until FROM spam_blocks WHERE user_lower = ?", (low,)).fetchone()
        blocked_until = float(blk["blocked_until"]) if blk else 0.0
        if blocked_until <= now and blk:
            conn.execute("DELETE FROM spam_blocks WHERE user_lower = ?", (low,))
            blocked_until = 0.0
        conn.execute("DELETE FROM spam_reports WHERE target_lower = ? AND ts < ?", (low, now - SPAM_WINDOW_SEC))
        rows = conn.execute("SELECT ts FROM spam_reports WHERE target_lower = ?", (low,)).fetchall()
        conn.commit()
        conn.close()
    return {
        "user": user_name,
        "blocked": blocked_until > now,
        "remaining_seconds": max(0, int(blocked_until - now)),
        "spam_count_24h": len(rows),
        "threshold": SPAM_THRESHOLD,
    }


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


def get_auth_token(token: str) -> dict | None:
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


def delete_auth_token(token: str):
    if not token:
        return
    with _DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM auth_tokens WHERE token = ?", (token,))
        conn.commit()
        conn.close()


def list_active_auth_tokens() -> list[dict]:
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
                is_reset = param.startswith("reset_")
                clean_param = param.replace("reset_", "", 1) if is_reset else param

                matched_rec = None
                for rec in active_tokens:
                    if now > rec.get("expires", 0):
                        continue
                    if clean_param and rec["token"].startswith(clean_param):
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
                    "text": "Tasdiqlash kodini Telegramga olish uchun pastdagi tugma orqali telefon raqamingizni yuboring:",
                    "reply_markup": {
                        "keyboard": [[{"text": "📱 Telefon raqamni yuborish", "request_contact": True}]],
                        "resize_keyboard": True,
                        "one_time_keyboard": True,
                    },
                })
                continue

            if contact.get("phone_number"):
                tg_digits = norm_phone(contact["phone_number"])
                sender_user_id = (msg.get("from") or {}).get("id")
                contact_user_id = contact.get("user_id")

                if sender_user_id and contact_user_id and sender_user_id != contact_user_id:
                    tg_api("sendMessage", {
                        "chat_id": chat_id,
                        "text": "❌ Faqat o'zingizning Telegram telefon raqamingizni yuborishingiz mumkin.",
                    })
                    continue

                matched = False
                for rec in active_tokens:
                    if now > rec.get("expires", 0):
                        continue
                    if rec.get("tg_chat_id") and str(rec.get("tg_chat_id")) != str(chat_id):
                        continue
                    if rec.get("phone_digits") == tg_digits:
                        matched = True
                        rec["tg_chat_id"] = str(chat_id)
                        rec["phone_matched"] = True
                        rec["verified"] = True
                        save_auth_token(rec["token"], rec)
                        action_label = "Parolni tiklash" if rec.get("mode") == "reset_password" else "Ro'yxatdan o'tish"
                        tg_api("sendMessage", {
                            "chat_id": chat_id,
                            "text": f"✅ Raqam tasdiqlandi ({action_label})!\nTasdiqlash kodi: <b>{rec['code']}</b>\nKod saytga ham avtomatik yuborildi.",
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


def _telegram_bg_worker():
    tg_api("deleteWebhook", {"drop_pending_updates": False})
    while True:
        try:
            sync_telegram_updates()
        except Exception as e:
            print(f"[TG_WORKER_ERR] {e}")
        time.sleep(2.0)


def ensure_telegram_bg_worker():
    global _TG_BG_STARTED
    if _TG_BG_STARTED:
        return
    _TG_BG_STARTED = True
    t = threading.Thread(target=_telegram_bg_worker, daemon=True)
    t.start()


ensure_telegram_bg_worker()


def parse_meta_from_text(raw_text: str) -> tuple[str, dict]:
    prefix = "__UZMETA__:"
    if raw_text and raw_text.startswith(prefix):
        nl = raw_text.find("\n")
        js = raw_text[len(prefix):nl] if nl >= 0 else raw_text[len(prefix):]
        try:
            meta = json.loads(js)
            if isinstance(meta, dict):
                cid = str(meta.get("chatId") or "__FAVORITES__")
                return cid, meta
        except Exception:
            pass
    return "__FAVORITES__", {"chatId": "__FAVORITES__"}


def row_to_chat(row) -> dict:
    try:
        members = json.loads(row["members_json"] or "[]")
    except Exception:
        members = []
    if not isinstance(members, list):
        members = []
    return {
        "id": row["id"],
        "title": row["title"],
        "username": row["username"] or "",
        "kind": row["kind"],
        "admin": row["admin"],
        "members": members,
        "created_at": float(row["created_at"] or 0),
    }


def get_chat_from_db(chat_id: str):
    if not chat_id:
        return None
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM chats WHERE id = ?", (chat_id,)).fetchone()
        conn.close()
    return row_to_chat(row) if row else None


def get_secret_chat_from_db(chat_id: str):
    if not chat_id:
        return None
    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM secret_chats WHERE id = ?", (chat_id,)).fetchone()
        conn.close()
    if not row:
        return None
    return {
        "id": row["id"],
        "user_a": row["user_a"],
        "user_b": row["user_b"],
        "auto_destruct_sec": int(row["auto_destruct_sec"] or 30),
        "created_at": float(row["created_at"] or 0),
    }


def list_secret_chats_for_user(user: dict) -> list[dict]:
    if not user:
        return []
    my_name = (user.get("name") or "").strip()
    my_low = my_name.lower()
    my_uname_low = (user.get("username") or "").lower()

    with _DB_LOCK:
        conn = get_db()
        rows = conn.execute("SELECT * FROM secret_chats ORDER BY created_at DESC").fetchall()
        conn.close()

    out = []
    for r in rows:
        a = (r["user_a"] or "").strip()
        b = (r["user_b"] or "").strip()
        a_low = a.lower()
        b_low = b.lower()
        if my_low in {a_low, b_low} or (my_uname_low and my_uname_low in {a_low, b_low}):
            peer = b if a_low in {my_low, my_uname_low} else a
            peer_u = get_user_by_username(peer) or (
                get_user_by_phone_digits(
                    next(
                        (
                            row["phone_digits"]
                            for row in get_db().execute("SELECT phone_digits, lower(name) AS ln FROM users").fetchall()
                            if row["ln"] == peer.lower()
                        ),
                        "",
                    )
                )
            )
            out.append({
                "id": r["id"],
                "title": peer,
                "username": peer_u["username"] if peer_u else "",
                "kind": "secret",
                "peerName": peer,
                "auto_destruct_sec": int(r["auto_destruct_sec"] or 30),
                "created_at": float(r["created_at"] or 0),
            })
    return out


def user_is_chat_member(chat: dict, user: dict) -> bool:
    if not chat or not user:
        return False
    members_low = {str(x).strip().lstrip("@").lower() for x in (chat.get("members") or [])}
    admin_low = str(chat.get("admin") or "").strip().lstrip("@").lower()
    my_name = (user.get("name") or "").strip().lower()
    my_uname = (user.get("username") or "").strip().lower()
    return (my_name and my_name in members_low) or (my_uname and my_uname in members_low) or (admin_low and admin_low in {my_name, my_uname})


def user_is_chat_admin(chat: dict, user: dict) -> bool:
    if not chat or not user:
        return False
    admin_low = str(chat.get("admin") or "").strip().lstrip("@").lower()
    my_name = (user.get("name") or "").strip().lower()
    my_uname = (user.get("username") or "").strip().lower()
    return bool(admin_low) and admin_low in {my_name, my_uname}


def can_access_chat_id(chat_id: str, user: dict) -> bool:
    if not user:
        return False
    cid = str(chat_id or "__FAVORITES__")
    my_name_low = (user.get("name") or "").lower()
    my_uname_low = (user.get("username") or "").lower()

    if cid == "__FAVORITES__":
        return True
    if cid.startswith("secret:"):
        sc = get_secret_chat_from_db(cid)
        if not sc:
            return False
        a_low = (sc.get("user_a") or "").lower()
        b_low = (sc.get("user_b") or "").lower()
        return (my_name_low and my_name_low in {a_low, b_low}) or (my_uname_low and my_uname_low in {a_low, b_low})
    if cid.startswith("dm:"):
        parts = [p.strip().lstrip("@").lower() for p in cid[3:].split("__")]
        return (my_name_low and my_name_low in parts) or (my_uname_low and my_uname_low in parts)
    chat = get_chat_from_db(cid)
    if not chat:
        return False
    return user_is_chat_member(chat, user)


def upsert_chat_in_db(chat_obj: dict):
    cid = str(chat_obj.get("id") or "").strip()
    if not cid or cid == "__FAVORITES__" or cid.startswith("dm:") or cid.startswith("secret:"):
        return
    title = str(chat_obj.get("title") or "").strip() or "Chat"
    uname = norm_username(chat_obj.get("username") or "")
    kind = str(chat_obj.get("kind") or "group")
    if kind not in {"group", "channel"}:
        kind = "group"
    admin = str(chat_obj.get("admin") or "").strip()
    members = []
    seen = set()
    for m in (chat_obj.get("members") or []):
        ms = str(m).strip()
        if ms and ms.lower() not in seen:
            seen.add(ms.lower())
            members.append(ms)
    if admin and admin.lower() not in seen:
        members.insert(0, admin)

    with _DB_LOCK:
        conn = get_db()
        existing = conn.execute("SELECT * FROM chats WHERE id = ?", (cid,)).fetchone()
        if not existing:
            conn.execute(
                "INSERT INTO chats(id, title, username, kind, admin, members_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (cid, title, uname, kind, admin, json.dumps(members, ensure_ascii=False), time.time()),
            )
        else:
            existing_chat = row_to_chat(existing)
            final_admin = existing_chat["admin"] or admin
            final_members = existing_chat["members"] if existing_chat["members"] else members
            final_uname = existing_chat["username"] or uname
            final_title = title or existing_chat["title"]
            conn.execute(
                "UPDATE chats SET title = ?, username = ?, admin = ?, members_json = ? WHERE id = ?",
                (final_title, final_uname, final_admin, json.dumps(final_members, ensure_ascii=False), cid),
            )
        conn.commit()
        conn.close()


@app.route("/")
def index():
    ensure_telegram_bg_worker()
    base_dir = os.path.dirname(os.path.abspath(__file__))
    index_path = os.path.join(base_dir, "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            html = f.read()
        return html.replace("{{ bot_username }}", str(BOT_USERNAME))
    return render_template("index.html", bot_username=BOT_USERNAME)


@app.post("/api/signup/start")
def signup_start():
    data = request.get_json(silent=True) or {}
    mode = (data.get("mode") or "signup").strip()
    name = (data.get("name") or "").strip()
    username = norm_username(data.get("username"))
    phone = (data.get("phone") or "").strip()
    digits = norm_phone(phone)

    if len(digits) < 7:
        return jsonify({"ok": False, "error": "Telefon raqami noto'g'ri yoki to'liq emas."}), 400

    code = f"{random.randint(100000, 999999)}"

    if mode == "reset_password":
        existing_user = get_user_by_phone_digits(digits)
        if not existing_user:
            return jsonify({"ok": False, "error": "Bu telefon raqam bilan profil topilmadi."}), 404
        token = str(uuid.uuid4())
        save_auth_token(token, {
            "mode": "reset_password",
            "phone_digits": digits,
            "code": code,
            "phone_matched": False,
            "verified": False,
            "tg_chat_id": None,
            "expires": time.time() + 600,
        })
        return jsonify({
            "ok": True,
            "token": token,
            "bot_url": f"https://t.me/{BOT_USERNAME}?start=reset_{token[:8]}",
        })

    if not name:
        return jsonify({"ok": False, "error": "Ism majburiy."}), 400
    if not username:
        return jsonify({"ok": False, "error": "@username majburiy."}), 400

    existing_by_phone = get_user_by_phone_digits(digits)
    if existing_by_phone:
        return jsonify({
            "ok": False,
            "error": (
                f"Bu raqamga @{existing_by_phone['username']} profili ochilgan. "
                "Boshqa profil ochib bo'lmaydi. Parolni unutgan bo'lsangiz, "
                "'Parolni unutdim' orqali tiking."
            ),
        }), 400

    if get_user_by_username(username):
        return jsonify({"ok": False, "error": f"@{username} band."}), 400

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
    if not rec or time.time() > rec["expires"]:
        return jsonify({"ok": False, "error": "Kod muddati tugagan."}), 404
    is_ver = bool(rec.get("verified") and rec.get("phone_matched"))
    return jsonify({
        "ok": True,
        "verified": is_ver,
        "code": rec.get("code") if is_ver else None,
    })


@app.post("/api/signup/complete")
def signup_complete():
    sync_telegram_updates()
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    code = (data.get("code") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm_password") or ""

    rec = get_auth_token(token)
    if not rec or rec.get("mode") != "signup" or time.time() > rec["expires"]:
        return jsonify({"ok": False, "error": "Sessiya topilmadi yoki muddati o'tgan."}), 400

    if not rec.get("verified") or not rec.get("phone_matched"):
        return jsonify({"ok": False, "error": "Avval Telegram botda telefon raqamingizni tasdiqlang."}), 400

    if not code or code != rec["code"]:
        return jsonify({"ok": False, "error": "Telegramdan kelgan kod noto'g'ri."}), 400

    if len(password) < 4 or password != confirm:
        return jsonify({"ok": False, "error": "Parol kamida 4 belgi va bir xil bo'lishi kerak."}), 400

    digits = rec["phone_digits"]
    if get_user_by_phone_digits(digits):
        return jsonify({"ok": False, "error": "Bu raqam allaqachon ro'yxatdan o'tgan."}), 400

    now = time.time()
    user = {
        "id": str(uuid.uuid4()),
        "name": rec["name"],
        "username": rec["username"],
        "phone": rec["phone"],
        "password_hash": hash_password(password),
        "bio": "",
        "last_seen": now,
    }
    with _DB_LOCK:
        conn = get_db()
        conn.execute(
            "INSERT INTO users(phone_digits, id, name, username, phone, password_hash, bio, last_seen) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
            (digits, user["id"], user["name"], user["username"], user["phone"], user["password_hash"], "", now),
        )
        conn.commit()
        conn.close()

    session["user_phone"] = digits
    delete_auth_token(token)
    return jsonify({"ok": True, "user": public_user(user)})


@app.post("/api/password/reset")
def password_reset():
    sync_telegram_updates()
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    digits = norm_phone(data.get("phone"))
    code = (data.get("code") or "").strip()
    new_password = data.get("new_password") or ""

    existing_user = get_user_by_phone_digits(digits)
    if not existing_user:
        return jsonify({"ok": False, "error": "Bu telefon raqam bilan profil topilmadi."}), 404

    rec = get_auth_token(token)
    if (
        not rec
        or rec.get("mode") != "reset_password"
        or rec.get("phone_digits") != digits
        or time.time() > rec.get("expires", 0)
    ):
        return jsonify({"ok": False, "error": "Sessiya topilmadi yoki muddati tugagan."}), 400

    if not rec.get("verified") or not rec.get("phone_matched"):
        return jsonify({"ok": False, "error": "Avval Telegram botda telefon raqamingizni yuborib mosligini tasdiqlang."}), 400

    if not code or code != rec["code"]:
        return jsonify({"ok": False, "error": "Telegramdan yuborilgan kod noto'g'ri."}), 400

    if len(new_password) < 4:
        return jsonify({"ok": False, "error": "Yangi parol kamida 4 belgidan iborat bo'lsin."}), 400

    now = time.time()
    new_hash = hash_password(new_password)
    with _DB_LOCK:
        conn = get_db()
        conn.execute("UPDATE users SET password_hash = ?, last_seen = ? WHERE phone_digits = ?", (new_hash, now, digits))
        conn.commit()
        conn.close()

    existing_user["last_seen"] = now
    session["user_phone"] = digits
    delete_auth_token(token)
    return jsonify({"ok": True, "user": public_user(existing_user)})


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    ident = (data.get("name") or data.get("phone") or "").strip()
    password = data.get("password") or ""

    user = find_user_by_phone_and_password(ident, password)
    if not user:
        return jsonify({"ok": False, "error": "Telefon raqam yoki parol noto'g'ri."}), 401

    now = time.time()
    digits = norm_phone(user["phone"])
    with _DB_LOCK:
        conn = get_db()
        conn.execute("UPDATE users SET last_seen = ? WHERE phone_digits = ?", (now, digits))
        conn.commit()
        conn.close()

    user["last_seen"] = now
    session["user_phone"] = digits
    return jsonify({"ok": True, "user": public_user(user)})


@app.post("/api/logout")
def logout():
    digits = session.get("user_phone")
    if digits:
        with _DB_LOCK:
            conn = get_db()
            conn.execute("UPDATE users SET last_seen = 0 WHERE phone_digits = ?", (digits,))
            conn.commit()
            conn.close()
    session.pop("user_phone", None)
    return jsonify({"ok": True})


@app.post("/api/profile")
def update_profile():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    digits = norm_phone(user["phone"])
    data = request.get_json(silent=True) or {}
    new_name = data["name"].strip() if data.get("name") else user["name"]
    new_uname = norm_username(data["username"]) if data.get("username") else user["username"]
    new_bio = (data.get("bio") or "").strip() if "bio" in data else user.get("bio", "")

    if not new_uname:
        new_uname = user["username"]

    with _DB_LOCK:
        conn = get_db()
        owner = conn.execute("SELECT phone_digits FROM users WHERE username = ?", (new_uname,)).fetchone()
        if owner and owner["phone_digits"] != digits:
            conn.close()
            return jsonify({"ok": False, "error": f"@{new_uname} allaqachon band."}), 400
        conn.execute(
            "UPDATE users SET name = ?, username = ?, bio = ? WHERE phone_digits = ?",
            (new_name, new_uname, new_bio, digits),
        )
        conn.commit()
        conn.close()

    user["name"] = new_name
    user["username"] = new_uname
    user["bio"] = new_bio
    return jsonify({"ok": True, "user": public_user(user)})


@app.get("/api/users/search")
def search_users():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    q = (request.args.get("q") or "").strip().lower()
    q_digits = norm_phone(q)
    q_uname = norm_username(q)
    out = []
    with _DB_LOCK:
        conn = get_db()
        rows = conn.execute("SELECT * FROM users").fetchall()
        conn.close()

    for r in rows:
        u = row_to_user(r)
        if (
            (q and (q in u["name"].lower() or q in u["username"].lower()))
            or (q_uname and q_uname in u["username"].lower())
            or (q_digits and q_digits in norm_phone(u["phone"]))
        ):
            out.append(public_user(u))
    return jsonify({"ok": True, "users": out})


@app.get("/api/chats")
def list_chats():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    q = (request.args.get("q") or "").strip().lower()
    q_uname = norm_username(q)

    with _DB_LOCK:
        conn = get_db()
        rows = conn.execute("SELECT * FROM chats ORDER BY created_at DESC").fetchall()
        conn.close()

    my_chats = list_secret_chats_for_user(user)
    public_search_chats = []

    for r in rows:
        c = row_to_chat(r)
        if user_is_chat_member(c, user):
            my_chats.append(c)
        if q and (
            q in c["title"].lower()
            or (q_uname and q_uname in (c["username"] or "").lower())
        ):
            public_search_chats.append({
                "id": c["id"],
                "title": c["title"],
                "username": c["username"],
                "kind": c["kind"],
                "admin": c["admin"],
                "members_count": len(c["members"]),
                "is_member": user_is_chat_member(c, user),
            })

    return jsonify({"ok": True, "chats": my_chats, "search_chats": public_search_chats})


@app.post("/api/secret-chats")
def create_secret_chat():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    data = request.get_json(silent=True) or {}
    peer_raw = (data.get("peer") or "").strip().lstrip("@")
    auto_destruct = int(data.get("auto_destruct_sec") or 30)
    if auto_destruct not in {0, 10, 30, 60}:
        auto_destruct = 30

    if not peer_raw:
        return jsonify({"ok": False, "error": "Maxfiy chat uchun foydalanuvchi tanlang."}), 400

    peer_user = get_user_by_username(peer_raw)
    if not peer_user:
        with _DB_LOCK:
            conn = get_db()
            row = conn.execute("SELECT * FROM users WHERE lower(name) = ?", (peer_raw.lower(),)).fetchone()
            conn.close()
        if row:
            peer_user = row_to_user(row)

    if not peer_user:
        return jsonify({"ok": False, "error": "Bunday foydalanuvchi topilmadi."}), 404

    peer_name = peer_user["name"]
    if peer_name.lower() == (user.get("name") or "").lower():
        return jsonify({"ok": False, "error": "O'zingiz bilan maxfiy chat ochib bo'lmaydi."}), 400

    pair = sorted([(user.get("name") or "").lower(), peer_name.lower()])
    cid = f"secret:{pair[0]}__{pair[1]}"
    now = time.time()

    with _DB_LOCK:
        conn = get_db()
        existing = conn.execute("SELECT * FROM secret_chats WHERE id = ?", (cid,)).fetchone()
        if existing:
            conn.execute("UPDATE secret_chats SET auto_destruct_sec = ? WHERE id = ?", (auto_destruct, cid))
        else:
            conn.execute(
                "INSERT INTO secret_chats(id, user_a, user_b, auto_destruct_sec, created_at) VALUES(?, ?, ?, ?, ?)",
                (cid, user.get("name"), peer_name, auto_destruct, now),
            )
        conn.commit()
        conn.close()

    return jsonify({
        "ok": True,
        "chat": {
            "id": cid,
            "title": peer_name,
            "username": peer_user.get("username") or "",
            "kind": "secret",
            "peerName": peer_name,
            "auto_destruct_sec": auto_destruct,
        },
    })


@app.put("/api/secret-chats/<path:chat_id>")
def update_secret_chat(chat_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401
    if not can_access_chat_id(chat_id, user):
        return jsonify({"ok": False, "error": "Ruxsat yo'q."}), 403

    data = request.get_json(silent=True) or {}
    auto_destruct = int(data.get("auto_destruct_sec") or 30)
    if auto_destruct not in {0, 10, 30, 60}:
        auto_destruct = 30

    with _DB_LOCK:
        conn = get_db()
        conn.execute("UPDATE secret_chats SET auto_destruct_sec = ? WHERE id = ?", (auto_destruct, chat_id))
        conn.commit()
        conn.close()

    return jsonify({"ok": True, "auto_destruct_sec": auto_destruct})


@app.post("/api/chats")
def create_chat():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    data = request.get_json(silent=True) or {}
    kind = (data.get("kind") or "group").strip().lower()
    if kind not in {"group", "channel"}:
        kind = "group"
    title = (data.get("title") or "").strip()
    if not title:
        return jsonify({"ok": False, "error": "Guruh yoki kanal nomi majburiy."}), 400

    uname = norm_username(data.get("username") or "")
    if uname:
        with _DB_LOCK:
            conn = get_db()
            dup = conn.execute("SELECT id FROM chats WHERE username = ?", (uname,)).fetchone()
            conn.close()
        if dup:
            return jsonify({"ok": False, "error": f"@{uname} nikneyk band."}), 400

    members = []
    seen = set()
    for m in [user["name"], *(data.get("members") or [])]:
        ms = str(m).strip().lstrip("@")
        if ms and ms.lower() not in seen:
            seen.add(ms.lower())
            members.append(ms)

    cid = f"{kind}:{uuid.uuid4().hex[:8]}_{re.sub(r'[^a-z0-9_]+', '_', title.lower()).strip('_') or 'chat'}"
    now = time.time()
    chat_obj = {
        "id": cid,
        "title": title,
        "username": uname,
        "kind": kind,
        "admin": user["name"],
        "members": members,
        "created_at": now,
    }
    with _DB_LOCK:
        conn = get_db()
        conn.execute(
            "INSERT INTO chats(id, title, username, kind, admin, members_json, created_at) VALUES(?, ?, ?, ?, ?, ?, ?)",
            (cid, title, uname, kind, user["name"], json.dumps(members, ensure_ascii=False), now),
        )
        conn.commit()
        conn.close()

    return jsonify({"ok": True, "chat": chat_obj})


@app.put("/api/chats/<path:chat_id>")
def update_chat(chat_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    chat = get_chat_from_db(chat_id)
    if not chat:
        return jsonify({"ok": False, "error": "Chat topilmadi."}), 404
    if not user_is_chat_admin(chat, user):
        return jsonify({"ok": False, "error": "Faqat admin tahrirlay oladi."}), 403

    data = request.get_json(silent=True) or {}
    new_title = (data.get("title") or chat["title"]).strip() or chat["title"]
    new_uname = norm_username(data["username"]) if "username" in data else chat["username"]

    if new_uname and new_uname != chat["username"]:
        with _DB_LOCK:
            conn = get_db()
            dup = conn.execute("SELECT id FROM chats WHERE username = ? AND id != ?", (new_uname, chat_id)).fetchone()
            conn.close()
        if dup:
            return jsonify({"ok": False, "error": f"@{new_uname} nikneyk band."}), 400

    with _DB_LOCK:
        conn = get_db()
        conn.execute("UPDATE chats SET title = ?, username = ? WHERE id = ?", (new_title, new_uname, chat_id))
        conn.commit()
        conn.close()

    chat["title"] = new_title
    chat["username"] = new_uname
    return jsonify({"ok": True, "chat": chat})


@app.post("/api/chats/<path:chat_id>/join")
def join_chat(chat_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    chat = get_chat_from_db(chat_id)
    if not chat:
        return jsonify({"ok": False, "error": "Guruh yoki kanal topilmadi."}), 404

    members = list(chat.get("members") or [])
    if not user_is_chat_member(chat, user):
        members.append(user["name"])
        with _DB_LOCK:
            conn = get_db()
            conn.execute("UPDATE chats SET members_json = ? WHERE id = ?", (json.dumps(members, ensure_ascii=False), chat_id))
            conn.commit()
            conn.close()
        chat["members"] = members

    return jsonify({"ok": True, "chat": chat})


@app.post("/api/chats/<path:chat_id>/leave")
def leave_chat(chat_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    chat = get_chat_from_db(chat_id)
    if not chat:
        return jsonify({"ok": False, "error": "Chat topilmadi."}), 404

    my_name_low = user["name"].lower()
    my_uname_low = user["username"].lower()
    remaining = [
        m for m in (chat.get("members") or [])
        if str(m).strip().lstrip("@").lower() not in {my_name_low, my_uname_low}
    ]

    with _DB_LOCK:
        conn = get_db()
        if not remaining or user_is_chat_admin(chat, user):
            conn.execute("DELETE FROM chats WHERE id = ?", (chat_id,))
            conn.execute("DELETE FROM messages WHERE chat_id = ?", (chat_id,))
            conn.commit()
            conn.close()
            return jsonify({"ok": True, "deleted": True})

        conn.execute("UPDATE chats SET members_json = ? WHERE id = ?", (json.dumps(remaining, ensure_ascii=False), chat_id))
        conn.execute(
            "DELETE FROM messages WHERE chat_id = ? AND (lower(sender) = ? OR lower(sender_username) = ?)",
            (chat_id, my_name_low, my_uname_low),
        )
        conn.commit()
        conn.close()

    chat["members"] = remaining
    return jsonify({"ok": True, "deleted": False, "chat": chat})


@app.delete("/api/chats/<path:chat_id>")
def delete_chat(chat_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    cid = str(chat_id)
    if cid == "__FAVORITES__":
        my_name_low = user["name"].lower()
        my_uname_low = user["username"].lower()
        with _DB_LOCK:
            conn = get_db()
            conn.execute(
                "DELETE FROM messages WHERE chat_id = '__FAVORITES__' AND (lower(sender) = ? OR lower(sender_username) = ?)",
                (my_name_low, my_uname_low),
            )
            conn.commit()
            conn.close()
        return jsonify({"ok": True, "deleted": True})

    if cid.startswith("secret:"):
        if not can_access_chat_id(cid, user):
            return jsonify({"ok": False, "error": "Ruxsat yo'q."}), 403
        with _DB_LOCK:
            conn = get_db()
            conn.execute("DELETE FROM secret_chats WHERE id = ?", (cid,))
            conn.execute("DELETE FROM messages WHERE chat_id = ?", (cid,))
            conn.commit()
            conn.close()
        return jsonify({"ok": True, "deleted": True})

    if cid.startswith("dm:"):
        if not can_access_chat_id(cid, user):
            return jsonify({"ok": False, "error": "Ruxsat yo'q."}), 403
        with _DB_LOCK:
            conn = get_db()
            conn.execute("DELETE FROM messages WHERE chat_id = ?", (cid,))
            conn.commit()
            conn.close()
        return jsonify({"ok": True, "deleted": True})

    chat = get_chat_from_db(cid)
    if not chat:
        return jsonify({"ok": False, "error": "Chat topilmadi."}), 404
    if not user_is_chat_admin(chat, user):
        return jsonify({"ok": False, "error": "Faqat admin guruh yoki kanalni o'chira oladi."}), 403

    with _DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM chats WHERE id = ?", (cid,))
        conn.execute("DELETE FROM messages WHERE chat_id = ?", (cid,))
        conn.commit()
        conn.close()
    return jsonify({"ok": True, "deleted": True})


@app.get("/api/messages")
def get_messages():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    ttl = int(request.args.get("ttl") or 0)
    now = time.time()

    with _DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM messages WHERE expire_at > 0 AND expire_at <= ?", (now,))
        if ttl > 0:
            conn.execute("DELETE FROM messages WHERE chat_id NOT LIKE 'secret:%' AND ts < ?", (now - ttl,))
        conn.commit()
        rows = conn.execute("SELECT * FROM messages ORDER BY ts ASC").fetchall()
        conn.close()

    my_name_low = user["name"].lower()
    my_uname_low = user["username"].lower()
    visible = []

    for r in rows:
        cid = r["chat_id"] or "__FAVORITES__"
        if not can_access_chat_id(cid, user):
            continue
        if cid == "__FAVORITES__":
            if (r["sender"] or "").lower() != my_name_low and (r["sender_username"] or "").lower() != my_uname_low:
                continue
        exp = float(r["expire_at"] or 0)
        rem = max(0, int(exp - now)) if exp > 0 else 0
        visible.append({
            "id": r["id"],
            "sender": r["sender"],
            "sender_username": r["sender_username"],
            "chat_id": cid,
            "text": r["text"] or "",
            "reply_to": r["reply_to"],
            "media_url": r["media_url"],
            "media_type": r["media_type"],
            "time": r["time_str"],
            "ts": float(r["ts"] or 0),
            "expire_at": exp,
            "remaining_sec": rem,
            "edited": bool(r["edited"]),
        })

    return jsonify({"ok": True, "messages": visible})


@app.post("/api/messages")
def create_message():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    sender = user["name"]
    text = request.form.get("text") or ""
    reply_to = (request.form.get("reply_to") or "").strip() or None
    chat_id, meta = parse_meta_from_text(text)

    if isinstance(meta.get("chatInfo"), dict):
        upsert_chat_in_db(meta["chatInfo"])

    if not can_access_chat_id(chat_id, user):
        return jsonify({"ok": False, "error": "Bu chatga yozish huquqingiz yo'q."}), 403

    chat = get_chat_from_db(chat_id)
    if chat and chat.get("kind") == "channel" and not user_is_chat_admin(chat, user):
        return jsonify({"ok": False, "error": "Kanalda faqat admin xabar yoza oladi."}), 403

    st = get_spam_status(sender)
    if st["blocked"]:
        return jsonify({
            "ok": False,
            "blocked": True,
            "remaining_seconds": st["remaining_seconds"],
            "error": "24 soatlik spam blok faol.",
        }), 403

    media_url = None
    media_type = None
    file = request.files.get("media")
    if file and file.filename:
        orig_name = os.path.basename(file.filename)
        ext = os.path.splitext(orig_name)[1].lower()
        mime = (file.mimetype or "").lower()
        safe_name = f"{uuid.uuid4().hex}{ext}"
        file.save(os.path.join(UPLOAD_DIR, safe_name))
        media_url = f"/static/uploads/{safe_name}"

        if mime.startswith("image/") or ext in {".png", ".jpg", ".jpeg", ".webp", ".gif"}:
            media_type = "image"
        elif mime.startswith("video/") or ext in {".mp4", ".webm", ".mov"}:
            media_type = "video"
        elif mime.startswith("audio/") or ext in {".mp3", ".ogg", ".wav", ".m4a", ".aac", ".flac"}:
            media_type = "audio"
        else:
            media_type = "file"

    now = time.time()
    expire_at = 0.0
    if str(chat_id).startswith("secret:"):
        sc = get_secret_chat_from_db(chat_id)
        sec = int(sc["auto_destruct_sec"]) if sc else 30
        if sec > 0:
            expire_at = now + sec

    msg = {
        "id": str(uuid.uuid4()),
        "sender": sender,
        "sender_username": user["username"],
        "chat_id": chat_id,
        "text": text,
        "reply_to": reply_to,
        "media_url": media_url,
        "media_type": media_type,
        "time": time.strftime("%H:%M"),
        "ts": now,
        "expire_at": expire_at,
        "remaining_sec": max(0, int(expire_at - now)) if expire_at > 0 else 0,
        "edited": False,
    }
    with _DB_LOCK:
        conn = get_db()
        conn.execute(
            """
            INSERT INTO messages(id, sender, sender_username, chat_id, text, reply_to, media_url, media_type, time_str, ts, expire_at, edited)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
            """,
            (
                msg["id"], msg["sender"], msg["sender_username"], msg["chat_id"],
                msg["text"], msg["reply_to"], msg["media_url"], msg["media_type"],
                msg["time"], msg["ts"], msg["expire_at"],
            ),
        )
        conn.commit()
        conn.close()

    return jsonify({"ok": True, "message": msg})


@app.put("/api/messages/<msg_id>")
def edit_message(msg_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"ok": False, "error": "Xabar topilmadi."}), 404

        sender_low = (row["sender"] or "").lower()
        if sender_low != user["name"].lower() and (row["sender_username"] or "").lower() != user["username"].lower():
            conn.close()
            return jsonify({"ok": False, "error": "Faqat o'z xabaringizni tahrirlashingiz mumkin."}), 403

        data = request.get_json(silent=True) or {}
        new_text = data["text"] if "text" in data else (row["text"] or "")
        new_cid, meta = parse_meta_from_text(new_text)
        if isinstance(meta.get("chatInfo"), dict):
            upsert_chat_in_db(meta["chatInfo"])

        conn.execute("UPDATE messages SET text = ?, chat_id = ?, edited = 1 WHERE id = ?", (new_text, new_cid, msg_id))
        conn.commit()
        updated = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
        conn.close()

    return jsonify({
        "ok": True,
        "message": {
            "id": updated["id"],
            "sender": updated["sender"],
            "sender_username": updated["sender_username"],
            "chat_id": updated["chat_id"],
            "text": updated["text"] or "",
            "reply_to": updated["reply_to"],
            "media_url": updated["media_url"],
            "media_type": updated["media_type"],
            "time": updated["time_str"],
            "ts": float(updated["ts"] or 0),
            "edited": bool(updated["edited"]),
        },
    })


@app.delete("/api/messages/<msg_id>")
def delete_message(msg_id: str):
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    with _DB_LOCK:
        conn = get_db()
        row = conn.execute("SELECT * FROM messages WHERE id = ?", (msg_id,)).fetchone()
        if not row:
            conn.close()
            return jsonify({"ok": False, "error": "Xabar topilmadi."}), 404

        sender_low = (row["sender"] or "").lower()
        if sender_low != user["name"].lower() and (row["sender_username"] or "").lower() != user["username"].lower():
            conn.close()
            return jsonify({"ok": False, "error": "Faqat o'z xabaringizni o'chirishingiz mumkin."}), 403

        conn.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
        conn.commit()
        conn.close()

    return jsonify({"ok": True})


@app.post("/api/spam/report")
def spam_report():
    user = get_current_user()
    if not user:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip().lower()
    if not target:
        return jsonify({"ok": False, "error": "Target ko'rsatilmagan."}), 400
    now = time.time()
    with _DB_LOCK:
        conn = get_db()
        conn.execute("DELETE FROM spam_reports WHERE target_lower = ? AND ts < ?", (target, now - SPAM_WINDOW_SEC))
        conn.execute("INSERT INTO spam_reports(target_lower, ts) VALUES(?, ?)", (target, now))
        cnt = conn.execute("SELECT COUNT(*) AS c FROM spam_reports WHERE target_lower = ?", (target,)).fetchone()["c"]
        if cnt >= SPAM_THRESHOLD:
            conn.execute(
                "INSERT INTO spam_blocks(user_lower, blocked_until) VALUES(?, ?) ON CONFLICT(user_lower) DO UPDATE SET blocked_until = excluded.blocked_until",
                (target, now + SPAM_BLOCK_SEC),
            )
        conn.commit()
        conn.close()

    return jsonify({"ok": True, "status": get_spam_status(target)})


@app.post("/api/spam/dismiss")
def spam_dismiss():
    return jsonify({"ok": True})


@app.get("/api/spam/status")
def spam_status():
    user = (request.args.get("user") or "").strip()
    if not user:
        cur = get_current_user()
        user = cur["name"] if cur else ""
    return jsonify({"ok": True, **get_spam_status(user)})


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


if __name__ == "__main__":
    ensure_telegram_bg_worker()
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
