import hashlib
import hmac
import json
import os
import random
import re
import time
import urllib.request
import uuid
from flask import Flask, jsonify, render_template, request, send_from_directory, session

app = Flask(__name__, template_folder=".", static_folder="static")
app.secret_key = os.environ.get("SECRET_KEY", "uzchat-secret-key")

BOT_TOKEN = os.environ.get("BOT_TOKEN", "")
BOT_USERNAME = os.environ.get("BOT_USERNAME", "FarruxCodeWorkbot")
UPLOAD_DIR = os.path.join(app.static_folder, "uploads")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(app.template_folder, exist_ok=True)

USERS_BY_PHONE = {}     # phone_digits -> user dict
USERS_BY_USERNAME = {}  # username -> phone_digits
AUTH_TOKENS = {}        # token -> dict
MESSAGES = []           # message dicts
SPAM_REPORTS = {}       # target_lower -> [timestamps]
SPAM_BLOCKS = {}        # user_lower -> blocked_until_timestamp
SPAM_THRESHOLD = 3
SPAM_WINDOW_SEC = 86400
SPAM_BLOCK_SEC = 86400
LAST_UPDATE_ID = 0


def norm_phone(p: str) -> str:
    return re.sub(r"\D", "", p or "")


def norm_username(u: str) -> str:
    return re.sub(r"[^a-z0-9_]", "", (u or "").strip().lstrip("@").lower())


def hash_password(raw: str) -> str:
    salt = app.secret_key.encode("utf-8")
    return hmac.new(salt, (raw or "").encode("utf-8"), hashlib.sha256).hexdigest()


def public_user(user: dict) -> dict:
    return {
        "id": user["id"],
        "name": user["name"],
        "username": user["username"],
        "phone": user["phone"],
        "bio": user.get("bio", ""),
    }


def find_user_by_phone_and_password(phone_or_ident: str, password: str):
    digits = norm_phone(phone_or_ident)
    if not digits or digits not in USERS_BY_PHONE:
        return None
    user = USERS_BY_PHONE[digits]
    if not password or not hmac.compare_digest(user.get("password_hash", ""), hash_password(password)):
        return None
    return user


def get_spam_status(user_name: str) -> dict:
    low = (user_name or "").strip().lower()
    now = time.time()
    blocked_until = SPAM_BLOCKS.get(low, 0)
    if blocked_until <= now and low in SPAM_BLOCKS:
        del SPAM_BLOCKS[low]
        blocked_until = 0
    reports = [t for t in SPAM_REPORTS.get(low, []) if now - t <= SPAM_WINDOW_SEC]
    SPAM_REPORTS[low] = reports
    return {
        "user": user_name,
        "blocked": blocked_until > now,
        "remaining_seconds": max(0, int(blocked_until - now)),
        "spam_count_24h": len(reports),
        "threshold": SPAM_THRESHOLD,
    }


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
        with urllib.request.urlopen(req, timeout=6) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def sync_telegram_updates():
    """Ro'yxatdan o'tish va parol tiklashda bot orqali kontakt raqamini tekshiradi va kodni Telegramga yuboradi."""
    global LAST_UPDATE_ID
    params = {"timeout": 0, "allowed_updates": ["message"]}
    if LAST_UPDATE_ID:
        params["offset"] = LAST_UPDATE_ID + 1

    res = tg_api("getUpdates", params)
    if not res or not res.get("ok"):
        return

    now = time.time()
    for upd in res.get("result", []):
        upd_id = upd.get("update_id", 0)
        if upd_id >= LAST_UPDATE_ID:
            LAST_UPDATE_ID = upd_id

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

            matched_token = None
            for tok, rec in AUTH_TOKENS.items():
                if now > rec.get("expires", 0):
                    continue
                if clean_param and tok.startswith(clean_param):
                    matched_token = tok
                    break

            if not matched_token:
                for tok, rec in reversed(list(AUTH_TOKENS.items())):
                    if now <= rec.get("expires", 0) and not rec.get("tg_chat_id"):
                        matched_token = tok
                        break

            if matched_token:
                AUTH_TOKENS[matched_token]["tg_chat_id"] = chat_id

            tg_api("sendMessage", {
                "chat_id": chat_id,
                "text": "Xavfsizlik uchun pastdagi tugma orqali telefon raqamingizni yuboring. Raqam saytdagi raqam bilan mos kelsa, tasdiqlash kodi shu yerga yuboriladi:",
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
            for tok, rec in AUTH_TOKENS.items():
                if now > rec.get("expires", 0):
                    continue
                if rec.get("tg_chat_id") and rec.get("tg_chat_id") != chat_id:
                    continue
                if rec.get("phone_digits") == tg_digits:
                    matched = True
                    rec["tg_chat_id"] = chat_id
                    rec["phone_matched"] = True
                    rec["verified"] = True
                    action_label = "Parolni tiklash" if rec.get("mode") == "reset_password" else "Ro'yxatdan o'tish"
                    tg_api("sendMessage", {
                        "chat_id": chat_id,
                        "text": f"✅ Raqam tasdiqlandi ({action_label})!\nTasdiqlash kodi: <b>{rec['code']}</b>\nUshbu kodni saytga kiriting.",
                        "parse_mode": "HTML",
                        "reply_markup": {"remove_keyboard": True},
                    })

            if not matched:
                tg_api("sendMessage", {
                    "chat_id": chat_id,
                    "text": "❌ Yuborilgan telefon raqam saytda kiritilgan raqam bilan mos kelmadi.",
                })


@app.route("/")
def index():
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
        if digits not in USERS_BY_PHONE:
            return jsonify({"ok": False, "error": "Bu telefon raqam bilan profil topilmadi."}), 404
        token = str(uuid.uuid4())
        AUTH_TOKENS[token] = {
            "mode": "reset_password",
            "phone_digits": digits,
            "code": code,
            "phone_matched": False,
            "verified": False,
            "tg_chat_id": None,
            "expires": time.time() + 600,
        }
        return jsonify({
            "ok": True,
            "token": token,
            "bot_url": f"https://t.me/{BOT_USERNAME}?start=reset_{token[:8]}",
        })

    if not name:
        return jsonify({"ok": False, "error": "Ism majburiy."}), 400
    if not username:
        return jsonify({"ok": False, "error": "@username majburiy."}), 400

    if digits in USERS_BY_PHONE:
        existing = USERS_BY_PHONE[digits]
        return jsonify({
            "ok": False,
            "error": (
                f"Bu raqamga @{existing['username']} profili ochilgan. "
                "Boshqa profil ochib bo'lmaydi. Parolni unutgan bo'lsangiz, "
                "'Parolni unutdim' orqali tiking."
            ),
        }), 400

    if username in USERS_BY_USERNAME:
        return jsonify({"ok": False, "error": f"@{username} band."}), 400

    token = str(uuid.uuid4())
    AUTH_TOKENS[token] = {
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
    }
    return jsonify({
        "ok": True,
        "token": token,
        "bot_url": f"https://t.me/{BOT_USERNAME}?start={token[:8]}",
    })


@app.get("/api/signup/status/<token>")
def signup_status(token: str):
    sync_telegram_updates()
    rec = AUTH_TOKENS.get(token)
    if not rec or time.time() > rec["expires"]:
        return jsonify({"ok": False, "error": "Kod muddati tugagan."}), 404
    return jsonify({
        "ok": True,
        "verified": bool(rec.get("verified") and rec.get("phone_matched")),
    })


@app.post("/api/signup/complete")
def signup_complete():
    sync_telegram_updates()
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    code = (data.get("code") or "").strip()
    password = data.get("password") or ""
    confirm = data.get("confirm_password") or ""

    rec = AUTH_TOKENS.get(token)
    if not rec or rec.get("mode") != "signup" or time.time() > rec["expires"]:
        return jsonify({"ok": False, "error": "Sessiya topilmadi yoki muddati o'tgan."}), 400

    if not rec.get("verified") or not rec.get("phone_matched"):
        return jsonify({"ok": False, "error": "Avval Telegram botda telefon raqamingizni tasdiqlang."}), 400

    if not code or code != rec["code"]:
        return jsonify({"ok": False, "error": "Telegramdan kelgan kod noto'g'ri."}), 400

    if len(password) < 4 or password != confirm:
        return jsonify({"ok": False, "error": "Parol kamida 4 belgi va bir xil bo'lishi kerak."}), 400

    digits = rec["phone_digits"]
    if digits in USERS_BY_PHONE:
        return jsonify({"ok": False, "error": "Bu raqam allaqachon ro'yxatdan o'tgan."}), 400

    user = {
        "id": str(uuid.uuid4()),
        "name": rec["name"],
        "username": rec["username"],
        "phone": rec["phone"],
        "password_hash": hash_password(password),
        "bio": "",
    }
    USERS_BY_PHONE[digits] = user
    USERS_BY_USERNAME[rec["username"]] = digits
    session["user_phone"] = digits
    AUTH_TOKENS.pop(token, None)
    return jsonify({"ok": True, "user": public_user(user)})


@app.post("/api/password/reset")
def password_reset():
    sync_telegram_updates()
    data = request.get_json(silent=True) or {}
    token = (data.get("token") or "").strip()
    digits = norm_phone(data.get("phone"))
    code = (data.get("code") or "").strip()
    new_password = data.get("new_password") or ""

    if digits not in USERS_BY_PHONE:
        return jsonify({"ok": False, "error": "Bu telefon raqam bilan profil topilmadi."}), 404

    rec = AUTH_TOKENS.get(token)
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

    user = USERS_BY_PHONE[digits]
    user["password_hash"] = hash_password(new_password)
    session["user_phone"] = digits
    AUTH_TOKENS.pop(token, None)
    return jsonify({"ok": True, "user": public_user(user)})


@app.post("/api/login")
def login():
    data = request.get_json(silent=True) or {}
    ident = (data.get("name") or data.get("phone") or "").strip()
    password = data.get("password") or ""

    user = find_user_by_phone_and_password(ident, password)
    if not user:
        return jsonify({"ok": False, "error": "Telefon raqam yoki parol noto'g'ri."}), 401

    session["user_phone"] = norm_phone(user["phone"])
    return jsonify({"ok": True, "user": public_user(user)})


@app.post("/api/logout")
def logout():
    session.pop("user_phone", None)
    return jsonify({"ok": True})


@app.post("/api/profile")
def update_profile():
    data = request.get_json(silent=True) or {}
    digits = session.get("user_phone")
    if not digits or digits not in USERS_BY_PHONE:
        return jsonify({"ok": False, "error": "Avval tizimga kiring."}), 401

    u = USERS_BY_PHONE[digits]
    if data.get("name"):
        u["name"] = data["name"].strip()
    if data.get("username"):
        new_u = norm_username(data["username"])
        if new_u:
            owner = USERS_BY_USERNAME.get(new_u)
            if owner and owner != digits:
                return jsonify({"ok": False, "error": f"@{new_u} allaqachon band."}), 400
            USERS_BY_USERNAME.pop(u["username"], None)
            u["username"] = new_u
            USERS_BY_USERNAME[new_u] = digits
    if "bio" in data:
        u["bio"] = (data.get("bio") or "").strip()
    return jsonify({"ok": True, "user": public_user(u)})


@app.get("/api/users/search")
def search_users():
    q = (request.args.get("q") or "").strip().lower()
    q_digits = norm_phone(q)
    q_uname = norm_username(q)
    out = []
    for u in USERS_BY_PHONE.values():
        if (
            (q and (q in u["name"].lower() or q in u["username"].lower()))
            or (q_uname and q_uname in u["username"].lower())
            or (q_digits and q_digits in norm_phone(u["phone"]))
        ):
            out.append(public_user(u))
    return jsonify({"ok": True, "users": out})


@app.get("/api/messages")
def get_messages():
    ttl = int(request.args.get("ttl") or 0)
    now = time.time()
    if ttl > 0:
        MESSAGES[:] = [m for m in MESSAGES if now - m.get("ts", now) <= ttl]
    return jsonify({"ok": True, "messages": MESSAGES})


@app.post("/api/messages")
def create_message():
    sender = (request.form.get("sender") or "").strip()
    text = request.form.get("text") or ""
    reply_to = (request.form.get("reply_to") or "").strip() or None

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

    msg = {
        "id": str(uuid.uuid4()),
        "sender": sender or "Foydalanuvchi",
        "text": text,
        "reply_to": reply_to,
        "media_url": media_url,
        "media_type": media_type,
        "time": time.strftime("%H:%M"),
        "ts": time.time(),
        "edited": False,
    }
    MESSAGES.append(msg)
    return jsonify({"ok": True, "message": msg})


@app.put("/api/messages/<msg_id>")
def edit_message(msg_id: str):
    data = request.get_json(silent=True) or {}
    for m in MESSAGES:
        if m["id"] == msg_id:
            if "text" in data:
                m["text"] = data["text"]
            m["edited"] = True
            return jsonify({"ok": True, "message": m})
    return jsonify({"ok": False, "error": "Xabar topilmadi."}), 404


@app.delete("/api/messages/<msg_id>")
def delete_message(msg_id: str):
    global MESSAGES
    before = len(MESSAGES)
    MESSAGES = [m for m in MESSAGES if m["id"] != msg_id]
    return jsonify({"ok": len(MESSAGES) < before})


@app.post("/api/spam/report")
def spam_report():
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip().lower()
    if not target:
        return jsonify({"ok": False, "error": "Target ko'rsatilmagan."}), 400
    now = time.time()
    arr = [t for t in SPAM_REPORTS.get(target, []) if now - t <= SPAM_WINDOW_SEC]
    arr.append(now)
    SPAM_REPORTS[target] = arr
    if len(arr) >= SPAM_THRESHOLD:
        SPAM_BLOCKS[target] = now + SPAM_BLOCK_SEC
    return jsonify({"ok": True, "status": get_spam_status(target)})


@app.post("/api/spam/dismiss")
def spam_dismiss():
    return jsonify({"ok": True})


@app.get("/api/spam/status")
def spam_status():
    user = request.args.get("user") or ""
    return jsonify({"ok": True, **get_spam_status(user)})


@app.route("/uploads/<path:filename>")
def uploaded_file(filename):
    return send_from_directory(UPLOAD_DIR, filename)


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)
