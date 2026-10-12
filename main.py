ELFA marketplace backend (FastAPI + SQLite)

Qurulum:
    pip install fastapi "uvicorn[standard]"

İşə salma:
    set ADMIN_TOKEN=guclu-gizli-token        (Windows)
    export ADMIN_TOKEN=guclu-gizli-token     (Mac/Linux)
    uvicorn main:app --reload

Sonra brauzerdə: http://127.0.0.1:8000
"""
import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("ELFA_DB", str(BASE_DIR / "elfa.db"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")  # boşdursa admin endpointləri bağlıdır
SESSION_DAYS = 14

app = FastAPI(title="ELFA API")


# ---------- Verilənlər bazası ----------
@contextmanager
def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    try:
        yield con
        con.commit()
    finally:
        con.close()


def init_db():
    with db() as con:
        con.executescript(
            """
            CREATE TABLE IF NOT EXISTS sellers (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                store_name TEXT NOT NULL,
                owner_name TEXT NOT NULL,
                category TEXT NOT NULL,
                phone TEXT NOT NULL,
                email TEXT NOT NULL UNIQUE,
                city TEXT DEFAULT '',
                about TEXT DEFAULT '',
                pw_salt TEXT NOT NULL,
                pw_hash TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'pending',  -- pending | approved | rejected
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                seller_id INTEGER NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS products (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                seller_id INTEGER NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                price REAL NOT NULL,
                stock INTEGER NOT NULL,
                image_url TEXT DEFAULT '',
                description TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id);
            """
        )


init_db()


# ---------- Köməkçilər ----------
def now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), 200_000)
    return salt, h.hex()


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Giriş tələb olunur")
    return authorization[7:].strip()


def current_seller(authorization: Optional[str] = Header(None)) -> sqlite3.Row:
    token = bearer(authorization)
    with db() as con:
        row = con.execute(
            """SELECT s.* , se.expires_at FROM sessions se
               JOIN sellers s ON s.id = se.seller_id
               WHERE se.token_hash = ?""",
            (sha(token),),
        ).fetchone()
    if not row or datetime.fromisoformat(row["expires_at"]) < now():
        raise HTTPException(401, "Sessiya bitib, yenidən daxil olun")
    return row


def require_admin(authorization: Optional[str] = Header(None)):
    if not ADMIN_TOKEN:
        raise HTTPException(503, "Admin girişi söndürülüb (ADMIN_TOKEN təyin edilməyib)")
    if not hmac.compare_digest(bearer(authorization), ADMIN_TOKEN):
        raise HTTPException(403, "İcazə yoxdur")


# Frontend {"error": "..."} formatını gözləyir
@app.exception_handler(HTTPException)
async def http_exc(_: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


@app.exception_handler(RequestValidationError)
async def validation_exc(_: Request, exc: RequestValidationError):
    return JSONResponse({"error": "Göndərilən məlumatlar düzgün deyil"}, status_code=422)


# ---------- Modellər ----------
class RegisterIn(BaseModel):
    store_name: str = Field(min_length=2, max_length=40)
    owner_name: str = Field(min_length=2, max_length=80)
    category: str = Field(min_length=1, max_length=40)
    phone: str
    email: str = Field(max_length=120)
    password: str = Field(min_length=6, max_length=100)
    city: str = Field(default="", max_length=60)
    about: str = Field(default="", max_length=500)


class LoginIn(BaseModel):
    email: str
    password: str


class ProductIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    price: float = Field(ge=0, le=1_000_000)
    stock: int = Field(ge=0, le=1_000_000)
    image_url: str = Field(default="", max_length=500)
    description: str = Field(default="", max_length=600)


class StatusIn(BaseModel):
    status: str


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^\+994\d{9}$")


# ---------- Satıcı: qeydiyyat və giriş ----------
@app.post("/api/sellers/register")
def register(data: RegisterIn):
    email = data.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "E-poçt düzgün deyil")
    phone = data.phone.replace(" ", "")
    if not PHONE_RE.match(phone):
        raise HTTPException(400, "Telefon nömrəsi düzgün deyil")
    salt, pw = hash_password(data.password)
    try:
        with db() as con:
            con.execute(
                """INSERT INTO sellers
                   (store_name, owner_name, category, phone, email, city, about,
                    pw_salt, pw_hash, status, created_at)
                   VALUES (?,?,?,?,?,?,?,?,?,'pending',?)""",
                (data.store_name.strip(), data.owner_name.strip(), data.category,
                 phone, email, data.city.strip(), data.about.strip(),
                 salt, pw, now().isoformat()),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Bu e-poçt artıq qeydiyyatdan keçib")
    return {"ok": True, "status": "pending"}


@app.post("/api/sellers/login")
def login(data: LoginIn):
    email = data.email.strip().lower()
    with db() as con:
        s = con.execute("SELECT * FROM sellers WHERE email = ?", (email,)).fetchone()
        # Eyni vaxt davranışı üçün hər halda hash hesablanır
        salt = s["pw_salt"] if s else "00" * 16
        _, h = hash_password(data.password, salt)
        if not s or not hmac.compare_digest(h, s["pw_hash"]):
            raise HTTPException(401, "E-poçt və ya şifrə yanlışdır")
        token = secrets.token_urlsafe(32)
        con.execute(
            "INSERT INTO sessions (token_hash, seller_id, expires_at) VALUES (?,?,?)",
            (sha(token), s["id"], (now() + timedelta(days=SESSION_DAYS)).isoformat()),
        )
        con.execute("DELETE FROM sessions WHERE expires_at < ?", (now().isoformat(),))
    return {"token": token, "store_name": s["store_name"], "status": s["status"]}


@app.get("/api/seller/me")
def me(s: sqlite3.Row = Depends(current_seller)):
    return {"store_name": s["store_name"], "email": s["email"], "status": s["status"]}


# ---------- Satıcı: məhsullar ----------
def product_dict(r: sqlite3.Row) -> dict:
    d = {k: r[k] for k in ("id", "name", "price", "stock", "image_url", "description")}
    if "store_name" in r.keys():
        d["store_name"] = r["store_name"]
    return d


@app.get("/api/seller/products")
def my_products(s: sqlite3.Row = Depends(current_seller)):
    with db() as con:
        rows = con.execute(
            "SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC", (s["id"],)
        ).fetchall()
    return [product_dict(r) for r in rows]


@app.post("/api/seller/products")
def add_product(data: ProductIn, s: sqlite3.Row = Depends(current_seller)):
    if s["status"] != "approved":
        raise HTTPException(403, "Mağazanız hələ təsdiqlənməyib")
    img = data.image_url.strip()
    if img and not re.match(r"^https?://", img, re.I):
        raise HTTPException(400, "Şəkil linki http(s) ilə başlamalıdır")
    with db() as con:
        cur = con.execute(
            """INSERT INTO products (seller_id, name, price, stock, image_url, description, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (s["id"], data.name.strip(), data.price, data.stock, img,
             data.description.strip(), now().isoformat()),
        )
        row = con.execute("SELECT * FROM products WHERE id = ?", (cur.lastrowid,)).fetchone()
    return product_dict(row)


@app.delete("/api/seller/products/{pid}")
def delete_product(pid: int, s: sqlite3.Row = Depends(current_seller)):
    with db() as con:
        cur = con.execute("DELETE FROM products WHERE id = ? AND seller_id = ?", (pid, s["id"]))
    if cur.rowcount == 0:
        raise HTTPException(404, "Məhsul tapılmadı")
    return {"ok": True}


# ---------- İctimai: ana səhifə məhsulları (yalnız təsdiqlənmiş satıcılar) ----------
@app.get("/api/products")
def public_products():
    with db() as con:
        rows = con.execute(
            """SELECT p.*, s.store_name FROM products p
               JOIN sellers s ON s.id = p.seller_id
               WHERE s.status = 'approved' AND p.stock > 0
               ORDER BY p.id DESC LIMIT 200"""
        ).fetchall()
    return [product_dict(r) for r in rows]


# ---------- Admin ----------
@app.get("/api/admin/sellers", dependencies=[Depends(require_admin)])
def admin_sellers(status: Optional[str] = None):
    q = """SELECT id, store_name, owner_name, category, phone, email, city, about, status, created_at
           FROM sellers"""
    args = ()
    if status:
        q += " WHERE status = ?"
        args = (status,)
    with db() as con:
        rows = con.execute(q + " ORDER BY id DESC", args).fetchall()
    return [dict(r) for r in rows]


@app.post("/api/admin/sellers/{sid}/status", dependencies=[Depends(require_admin)])
def admin_set_status(sid: int, data: StatusIn):
    if data.status not in ("pending", "approved", "rejected"):
        raise HTTPException(400, "Status yanlışdır")
    with db() as con:
        cur = con.execute("UPDATE sellers SET status = ? WHERE id = ?", (data.status, sid))
    if cur.rowcount == 0:
        raise HTTPException(404, "Satıcı tapılmadı")
    return {"ok": True, "status": data.status}


# ---------- Səhifələr ----------
def page(name: str):
    f = BASE_DIR / name
    if not f.is_file():
        raise HTTPException(404, "Səhifə tapılmadı")
    return FileResponse(f)


@app.get("/")
@app.get("/elfa.html")
def home():
    return page("index.html")


@app.get("/seller-register.html")
def seller_page():
    return page("seller-register.html")
