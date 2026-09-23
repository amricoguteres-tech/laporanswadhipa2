from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import hmac
import json
import os
import re
import secrets
import sqlite3
import time
import base64
from pathlib import Path
from urllib.parse import urlparse
from cryptography.fernet import Fernet, InvalidToken

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv("APP_DATA_DIR", str(BASE_DIR)))
DATA_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = DATA_DIR / "laporswadhipa2.db"
ADMIN_EMAIL = "admin@sekolah.id"
DEFAULT_ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD_DEFAULT", "Admin12345")
ADMIN_PASSWORD_HASH_PATH = DATA_DIR / ".admin_password_hash"
ENCRYPTION_KEY_PATH = DATA_DIR / ".app_encryption.key"
DEFAULT_ALLOWED_ORIGINS = {
    "https://dc818021.laporswadhipa2.pages.dev",
    "https://ebee416d.laporswadhipa2.pages.dev",
    "http://127.0.0.1:8000",
    "http://localhost:8000",
    "http://localhost:3000",
    "http://127.0.0.1:3000",
}
ALLOWED_ORIGIN = os.getenv("ALLOWED_ORIGIN", "https://dc818021.laporswadhipa2.pages.dev")
SESSION_TTL_SECONDS = 8 * 60 * 60
USER_DATA_FIELDS = ("email", "name", "className", "major")
ENCRYPTED_PREFIX = "enc$"
SESSIONS = {}
LOGIN_ATTEMPTS = {}
MAX_BODY_BYTES = 5 * 1024 * 1024
MASTER_CONFIG = {
    "rooms": {"label": "ruangan", "fields": ("name", "building", "capacity")},
    "tools": {"label": "alat praktik", "fields": ("name", "category", "quantity", "condition", "room")},
    "students": {"label": "siswa", "fields": ("nis", "email", "password", "name", "className", "major")},
    "teachers": {"label": "guru", "fields": ("nip", "name", "subject")},
}

SEED_REPORTS = [
    ("LR-2408", "Kipas angin tidak berputar", "Ruang Kelas SMK 1", "Elektronik", "Raka Aditya", "16 Sep 2026", "review", "Kipas angin di sisi jendela mengeluarkan suara dan tidak berputar."),
    ("LR-2407", "Lampu kelas mati", "Ruang Kelas SMK 2", "Kelistrikan", "Nadia Putri", "15 Sep 2026", "valid", "Dua lampu di baris belakang tidak menyala."),
    ("LR-2406", "Papan tulis perlu dibersihkan", "Bengkel TKR", "Kebersihan", "Fajar Maulana", "14 Sep 2026", "valid", "Permukaan papan tulis sulit dibersihkan dan meninggalkan bekas."),
    ("LR-2405", "Keran air bocor", "Toilet lantai 2", "Fasilitas", "Siti Rahma", "13 Sep 2026", "rejected", "Laporan ganda dari laporan sebelumnya."),
]


def db_connection():
    connection = sqlite3.connect(DATABASE_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def db_rows(table, where="", params=()):
    with db_connection() as connection:
        return [dict(row) for row in connection.execute(f"SELECT * FROM {table} {where} ORDER BY createdAt DESC", params)]


def db_one(table, where, params=()):
    rows = db_rows(table, where, params)
    return rows[0] if rows else None


def db_insert(table, item):
    columns = list(item)
    placeholders = ", ".join("?" for _ in columns)
    with db_connection() as connection:
        connection.execute(
            f"INSERT INTO {table} ({', '.join(columns)}) VALUES ({placeholders})",
            [item[column] for column in columns],
        )


def db_update(table, where, where_params, values):
    assignments = ", ".join(f"{column} = ?" for column in values)
    with db_connection() as connection:
        cursor = connection.execute(
            f"UPDATE {table} SET {assignments} WHERE {where}",
            [*values.values(), *where_params],
        )
        return cursor.rowcount


def db_delete(table, where, params):
    with db_connection() as connection:
        cursor = connection.execute(f"DELETE FROM {table} WHERE {where}", params)
        return cursor.rowcount


def init_db():
    with db_connection() as connection:
        connection.execute("""CREATE TABLE IF NOT EXISTS reports (
            id TEXT PRIMARY KEY, title TEXT NOT NULL, room TEXT NOT NULL,
            category TEXT NOT NULL, reporter TEXT NOT NULL, date TEXT NOT NULL,
            status TEXT NOT NULL, detail TEXT NOT NULL, createdAt TEXT NOT NULL
        )""")
        report_columns = {row[1] for row in connection.execute("PRAGMA table_info(reports)")}
        if "createdAt" not in report_columns:
            connection.execute("ALTER TABLE reports ADD COLUMN createdAt TEXT")
            connection.execute(
                "UPDATE reports SET createdAt = ? WHERE createdAt IS NULL",
                (datetime.now().isoformat(),),
            )
            report_columns.add("createdAt")
        if "photo" not in report_columns:
            connection.execute("ALTER TABLE reports ADD COLUMN photo TEXT")
        for name, config in MASTER_CONFIG.items():
            columns = ["id TEXT PRIMARY KEY"]
            columns.extend(f"{field} TEXT NOT NULL" for field in config["fields"])
            if name == "students":
                columns.append("banned INTEGER NOT NULL DEFAULT 0")
            columns.append("createdAt TEXT NOT NULL")
            connection.execute(f"CREATE TABLE IF NOT EXISTS {name} ({', '.join(columns)})")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS students_nis ON students(nis)")
        connection.execute("CREATE UNIQUE INDEX IF NOT EXISTS students_email ON students(email)")
        report_count = connection.execute("SELECT COUNT(*) FROM reports").fetchone()[0]
    if report_count == 0:
        now = datetime.now()
        for report in [
            {
                "id": report[0], "title": report[1], "room": report[2],
                "category": report[3], "reporter": report[4], "date": report[5],
                "status": report[6], "detail": report[7], "createdAt": now.isoformat(),
            }
            for report in SEED_REPORTS
        ]:
            db_insert("reports", report)

    migrate_student_data()


def report_json(row):
    report = dict(row)
    report.pop("createdAt", None)
    report["reporter"] = decrypt_user_value(report.get("reporter", ""))
    return report


def master_json(row):
    item = dict(row)
    item.pop("createdAt", None)
    item.pop("password", None)
    if "email" in item:
        for field in USER_DATA_FIELDS:
            item[field] = decrypt_user_value(item[field])
    if "banned" in item:
        item["banned"] = bool(item["banned"])
    return item


def hash_password(password):
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 210_000)
    return f"pbkdf2_sha256$210000${salt.hex()}${digest.hex()}"


def resolve_admin_password_hash():
    configured_hash = os.getenv("ADMIN_PASSWORD_HASH")
    if configured_hash:
        return configured_hash
    if ADMIN_PASSWORD_HASH_PATH.exists():
        stored_hash = ADMIN_PASSWORD_HASH_PATH.read_text(encoding="utf-8").strip()
        if stored_hash:
            return stored_hash
    default_hash = hash_password(DEFAULT_ADMIN_PASSWORD)
    ADMIN_PASSWORD_HASH_PATH.write_text(default_hash, encoding="utf-8")
    try:
        os.chmod(ADMIN_PASSWORD_HASH_PATH, 0o600)
    except OSError:
        pass
    return default_hash


def load_encryption_cipher():
    configured_key = os.getenv("APP_ENCRYPTION_KEY")
    candidate_keys = []

    if configured_key:
        candidate_keys.append(configured_key.encode("ascii"))
    if ENCRYPTION_KEY_PATH.exists():
        candidate_keys.append(ENCRYPTION_KEY_PATH.read_bytes().strip())

    if not candidate_keys:
        candidate_keys.append(Fernet.generate_key())
        ENCRYPTION_KEY_PATH.write_bytes(candidate_keys[0] + b"\n")
        try:
            os.chmod(ENCRYPTION_KEY_PATH, 0o600)
        except OSError:
            pass

    for key in candidate_keys:
        try:
            return Fernet(key)
        except (ValueError, TypeError):
            continue

    new_key = Fernet.generate_key()
    ENCRYPTION_KEY_PATH.write_bytes(new_key + b"\n")
    try:
        os.chmod(ENCRYPTION_KEY_PATH, 0o600)
    except OSError:
        pass
    print("APP_ENCRYPTION_KEY tidak valid; membuat kunci baru secara otomatis.")
    return Fernet(new_key)


ADMIN_PASSWORD_HASH = resolve_admin_password_hash()
ENCRYPTION_CIPHER = load_encryption_cipher()


def encrypt_user_value(value):
    if value.startswith(ENCRYPTED_PREFIX):
        return value
    return ENCRYPTED_PREFIX + ENCRYPTION_CIPHER.encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_user_value(value):
    if not value.startswith(ENCRYPTED_PREFIX):
        return value
    try:
        return ENCRYPTION_CIPHER.decrypt(value[len(ENCRYPTED_PREFIX):].encode("ascii")).decode("utf-8")
    except (InvalidToken, UnicodeDecodeError, ValueError):
        raise RuntimeError("Kan dekripsi data user. Periksa APP_ENCRYPTION_KEY atau file kunci.") from None


def migrate_student_data():
    students = db_rows("students")
    for student in students:
        values = {
            field: encrypt_user_value(student[field])
            for field in USER_DATA_FIELDS
        }
        if any(values[field] != student[field] for field in USER_DATA_FIELDS):
            db_update("students", "id = ?", (student["id"],), values)


def verify_password(password, stored):
    if stored.startswith("pbkdf2_sha256$"):
        try:
            _, rounds, salt_hex, digest_hex = stored.split("$", 3)
            digest = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), int(rounds))
            return hmac.compare_digest(digest.hex(), digest_hex)
        except (ValueError, TypeError):
            return False
    return hmac.compare_digest(password, stored)


def valid_identifier(value):
    return bool(re.fullmatch(r"[A-Za-z0-9._@+-]{1,120}", value or ""))


def valid_nis(value):
    return bool(re.fullmatch(r"[0-9]{1,120}", value or ""))


def allowed_origin_for(origin):
    if not origin:
        return ALLOWED_ORIGIN
    if origin in DEFAULT_ALLOWED_ORIGINS or origin == ALLOWED_ORIGIN:
        return origin
    if origin.startswith("https://") and origin.endswith(".pages.dev"):
        return origin
    if origin.startswith("http://localhost") or origin.startswith("http://127.0.0.1"):
        return origin
    return ALLOWED_ORIGIN


def clean_master_payload(collection_name, payload):
    config = MASTER_CONFIG[collection_name]
    if not isinstance(payload, dict):
        return None
    values = {field: str(payload.get(field, "")).strip() for field in config["fields"]}
    if any(not values[field] or len(values[field]) > 200 for field in config["fields"]):
        return None
    if collection_name == "students" and (not valid_nis(values["nis"]) or len(values["password"]) < 8 or not re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", values["email"])):
        return None
    return values


def parse_json(handler):
    length = int(handler.headers.get("Content-Length", "0"))
    if length > MAX_BODY_BYTES:
        return None
    try:
        return json.loads(handler.rfile.read(length) or b"{}")
    except json.JSONDecodeError:
        return None


def clean_photo(value):
    if not value:
        return ""
    if not isinstance(value, str) or not re.fullmatch(r"data:image/(?:jpeg|png|webp);base64,[A-Za-z0-9+/=]+", value):
        return None
    encoded = value.split(",", 1)[1]
    try:
        if len(base64.b64decode(encoded, validate=True)) > 3 * 1024 * 1024:
            return None
    except (ValueError, base64.binascii.Error):
        return None
    return value


def authenticated(handler):
    token = handler.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    return token in SESSIONS


def session_user(handler):
    token = handler.headers.get("Authorization", "").removeprefix("Bearer ").strip()
    session = SESSIONS.get(token)
    if session and session.get("expiresAt", 0) > time.time():
        return session
    if session:
        SESSIONS.pop(token, None)
    return None


def admin_authenticated(handler):
    user = session_user(handler)
    return user is not None and user.get("role") == "admin"


class AppHandler(BaseHTTPRequestHandler):
    def log_message(self, format_string, *args):
        print(f"{self.address_string()} - {format_string % args}")

    def send_json(self, status, payload):
        origin = self.headers.get("Origin")
        allowed_origin = allowed_origin_for(origin)
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", allowed_origin)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self' https://cdn.phototourl.com; connect-src 'self' https:; img-src 'self' https://cdn.phototourl.com data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        origin = self.headers.get("Origin")
        allowed_origin = allowed_origin_for(origin)
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", allowed_origin)
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/api/health":
            self.send_json(200, {"ok": True, "service": "SMKSWADHIPA2NATAR"})
            return
        if path == "/api/reports":
            user = session_user(self)
            if user is None:
                self.send_json(401, {"error": "Login diperlukan."})
                return
            if user.get("role") == "admin":
                rows = db_rows("reports")
            else:
                rows = [
                    row for row in db_rows("reports")
                    if decrypt_user_value(row.get("reporter", "")) == user.get("name")
                ]
            self.send_json(200, {"reports": [report_json(row) for row in rows]})
            return
        master_parts = path.strip("/").split("/")
        if len(master_parts) == 2 and master_parts[0] == "api" and master_parts[1] in MASTER_CONFIG:
            if not admin_authenticated(self):
                self.send_json(401, {"error": "Login admin diperlukan."})
                return
            rows = db_rows(master_parts[1])
            self.send_json(200, {master_parts[1]: [master_json(row) for row in rows]})
            return
        if path == "/" or path == "/index.html":
            self.serve_index()
            return
        self.send_json(404, {"error": "Rute tidak ditemukan."})

    def do_POST(self):
        path = urlparse(self.path).path
        payload = parse_json(self)
        if path == "/api/login":
            client = self.client_address[0]
            now = time.time()
            attempts = [stamp for stamp in LOGIN_ATTEMPTS.get(client, []) if now - stamp < 300]
            if len(attempts) >= 10:
                self.send_json(429, {"error": "Terlalu banyak percobaan login. Coba lagi beberapa menit lagi."})
                return
            attempts.append(now)
            LOGIN_ATTEMPTS[client] = attempts
            if not isinstance(payload, dict):
                self.send_json(400, {"error": "Data login tidak valid."})
                return
            is_admin_login = not payload.get("nis", "").strip() and bool(payload.get("email") or payload.get("password"))
            if is_admin_login:
                valid_login = payload.get("email", "").strip().lower() == ADMIN_EMAIL and bool(ADMIN_PASSWORD_HASH) and verify_password(str(payload.get("password", "")), ADMIN_PASSWORD_HASH)
                user = {"role": "admin", "name": "Bu Anisa Pratama"}
                error_message = "Email atau kata sandi admin salah."
            else:
                nis = payload.get("nis", "").strip()
                email = payload.get("email", "").strip().lower()
                password = payload.get("password", "")
                student = db_one("students", "WHERE nis = ?", (nis,)) if valid_nis(nis) and password else None
                password_valid = student is not None and verify_password(password, student.get("password", ""))
                valid_login = password_valid and not student.get("banned", False) if student else False
                if valid_login and not str(student.get("password", "")).startswith("pbkdf2_sha256$"):
                    db_update("students", "nis = ?", (nis,), {"password": hash_password(password)})
                user = {"role": "user", "nis": nis, "name": student.get("name", "Siswa") if student else "Siswa"}
                error_message = "Email, password, atau NISN siswa tidak valid; atau akun sedang dibanned."
            if not valid_login:
                self.send_json(401, {"error": error_message})
                return
            token = secrets.token_urlsafe(32)
            SESSIONS[token] = {**user, "expiresAt": time.time() + SESSION_TTL_SECONDS}
            self.send_json(200, {"token": token, **user})
            return
        if path == "/api/reports":
            if not authenticated(self):
                self.send_json(401, {"error": "Login admin diperlukan."})
                return
            required = ("title", "room", "category", "reporter", "detail")
            if not isinstance(payload, dict) or any(not str(payload.get(key, "")).strip() for key in required):
                self.send_json(400, {"error": "Data laporan belum lengkap."})
                return
            photo = clean_photo(payload.get("photo", ""))
            if photo is None:
                self.send_json(400, {"error": "Foto harus berupa JPG, PNG, atau WebP dan berukuran maksimal 3 MB."})
                return
            report_id = "LR-" + str(int(datetime.now().timestamp()))[-6:]
            report = {
                "id": report_id,
                "title": payload["title"].strip(),
                "room": payload["room"],
                "category": payload["category"],
                "reporter": session_user(self).get("name", payload["reporter"].strip()),
                "date": datetime.now().strftime("%d %b %Y"),
                "status": "review",
                "detail": payload["detail"].strip(),
                "photo": photo,
                "createdAt": datetime.now().isoformat(),
            }
            db_insert("reports", report)
            self.send_json(201, {"report": report_json(report)})
            return
        master_parts = path.strip("/").split("/")
        if len(master_parts) == 2 and master_parts[0] == "api" and master_parts[1] in MASTER_CONFIG:
            if not admin_authenticated(self):
                self.send_json(401, {"error": "Login admin diperlukan."})
                return
            collection_name = master_parts[1]
            values = clean_master_payload(collection_name, payload)
            if values is None:
                self.send_json(400, {"error": "Semua data wajib diisi."})
                return
            if collection_name == "students":
                values["email"] = values["email"].lower()
                if any(
                    decrypt_user_value(student["email"]).lower() == values["email"]
                    for student in db_rows("students")
                ):
                    self.send_json(409, {"error": "NISN atau email siswa sudah terdaftar."})
                    return
                values["password"] = hash_password(values["password"])
                for field in USER_DATA_FIELDS:
                    values[field] = encrypt_user_value(values[field])
            item = {"id": secrets.token_hex(5).upper(), **values, "createdAt": datetime.now().isoformat()}
            if collection_name == "students":
                item["banned"] = False
            try:
                db_insert(collection_name, item)
            except sqlite3.IntegrityError:
                if collection_name == "students":
                    self.send_json(409, {"error": "NISN atau email siswa sudah terdaftar."})
                else:
                    self.send_json(409, {"error": "Data dengan identitas tersebut sudah terdaftar."})
                return
            self.send_json(201, {"item": master_json(item)})
            return
        self.send_json(404, {"error": "Rute tidak ditemukan."})

    def do_PATCH(self):
        path_parts = urlparse(self.path).path.strip("/").split("/")
        if len(path_parts) == 4 and path_parts[:2] == ["api", "students"] and path_parts[3] == "ban":
            if not admin_authenticated(self):
                self.send_json(401, {"error": "Login admin diperlukan."})
                return
            payload = parse_json(self)
            banned = payload.get("banned") if isinstance(payload, dict) else None
            if not isinstance(banned, bool):
                self.send_json(400, {"error": "Status ban tidak valid."})
                return
            nis = path_parts[2]
            if not valid_nis(nis):
                self.send_json(400, {"error": "NISN tidak valid."})
                return
            result = db_update("students", "nis = ?", (nis,), {"banned": int(banned)})
            row = db_one("students", "WHERE nis = ?", (nis,))
            if result == 0 or row is None:
                self.send_json(404, {"error": "Siswa dengan NIS tersebut tidak ditemukan."})
                return
            self.send_json(200, {"student": master_json(row)})
            return
        if len(path_parts) != 4 or path_parts[:2] != ["api", "reports"] or path_parts[3] != "status":
            self.send_json(404, {"error": "Rute tidak ditemukan."})
            return
        if not admin_authenticated(self):
            self.send_json(401, {"error": "Login admin diperlukan."})
            return
        payload = parse_json(self)
        status = payload.get("status") if isinstance(payload, dict) else None
        if status not in ("valid", "rejected"):
            self.send_json(400, {"error": "Status tidak valid."})
            return
        report_id = path_parts[2]
        result = db_update("reports", "id = ?", (report_id,), {"status": status})
        row = db_one("reports", "WHERE id = ?", (report_id,))
        if result == 0 or row is None:
            self.send_json(404, {"error": "Laporan tidak ditemukan."})
            return
        self.send_json(200, {"report": report_json(row)})

    def do_DELETE(self):
        path_parts = urlparse(self.path).path.strip("/").split("/")
        if len(path_parts) != 3 or path_parts[0] != "api" or path_parts[1] not in ("rooms", "tools", "students"):
            self.send_json(404, {"error": "Rute tidak ditemukan."})
            return
        if not admin_authenticated(self):
            self.send_json(401, {"error": "Login admin diperlukan."})
            return
        collection_name = path_parts[1]
        item_id = path_parts[2]
        if not valid_identifier(item_id):
            self.send_json(400, {"error": "Identitas data tidak valid."})
            return
        identity_field = "nis" if collection_name == "students" else "id"
        result = db_delete(collection_name, f"{identity_field} = ?", (item_id,))
        if result == 0:
            self.send_json(404, {"error": "Data tidak ditemukan."})
            return
        self.send_json(200, {"message": "Data berhasil dihapus.", "id": item_id})

    def serve_index(self):
        content = (BASE_DIR / "index.html").read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self' https://cdn.phototourl.com; connect-src 'self' https:; img-src 'self' https://cdn.phototourl.com data:; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'")
        self.end_headers()
        self.wfile.write(content)


if __name__ == "__main__":
    init_db()
    print("SMKSWADHIPA2NATAR berjalan di http://0.0.0.0:8000 (akses LAN menggunakan IP komputer ini)")
    print(f"SQLite: {DATABASE_PATH}")
    print(f"Login admin: {ADMIN_EMAIL} (password default lokal: {DEFAULT_ADMIN_PASSWORD})")
    port = int(os.getenv("PORT", "8000"))
    ThreadingHTTPServer(("0.0.0.0", port), AppHandler).serve_forever()
