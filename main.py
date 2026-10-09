import hashlib
import hmac
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Depends, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, Field

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.getenv("ELFA_DB_PATH", str(ROOT / "data" / "elfa.sqlite3")))
DB_PATH.parent.mkdir(parents=True, exist_ok=True)
SESSION_DAYS = 7
COOKIE_NAME = "elfa_session"
COOKIE_SECURE = os.getenv("COOKIE_SECURE", "0") == "1"

app = FastAPI(title="ELFA Marketplace API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://127.0.0.1:8000", "http://localhost:8000"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PATCH", "DELETE"],
    allow_headers=["Content-Type"],
)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def db():
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con

def hash_password(password: str, salt: Optional[bytes] = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 260_000)
    return salt.hex() + "$" + digest.hex()

def verify_password(password: str, saved: str) -> bool:
    try:
        salt_hex, digest_hex = saved.split("$", 1)
        candidate = hash_password(password, bytes.fromhex(salt_hex)).split("$", 1)[1]
        return hmac.compare_digest(candidate, digest_hex)
    except Exception:
        return False

def init_db():
    with db() as con:
        con.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT NOT NULL UNIQUE,
            full_name TEXT NOT NULL,
            phone TEXT NOT NULL,
            store_name TEXT NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'seller',
            status TEXT NOT NULL DEFAULT 'pending',
            created_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS sessions (
            token_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            seller_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            name TEXT NOT NULL,
            description TEXT NOT NULL DEFAULT '',
            category TEXT NOT NULL DEFAULT '',
            price REAL NOT NULL CHECK(price >= 0),
            stock INTEGER NOT NULL DEFAULT 0 CHECK(stock >= 0),
            image_url TEXT NOT NULL DEFAULT '',
            active INTEGER NOT NULL DEFAULT 1,
            created_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id);
        CREATE INDEX IF NOT EXISTS idx_products_active ON products(active);
        """)
    # Admin account is created only when credentials are explicitly configured.
    admin_email = os.getenv("ADMIN_EMAIL", "").strip().lower()
    admin_password = os.getenv("ADMIN_PASSWORD", "")
    if admin_email and admin_password:
        with db() as con:
            row = con.execute("SELECT id FROM users WHERE email=?", (admin_email,)).fetchone()
            if row:
                con.execute("UPDATE users SET role='admin', status='approved' WHERE email=?", (admin_email,))
            else:
                con.execute(
                    """INSERT INTO users(email,full_name,phone,store_name,password_hash,role,status,created_at)
                       VALUES(?,?,?,?,?,'admin','approved',?)""",
                    (admin_email, "ELFA Administrator", "", "ELFA Admin",
                     hash_password(admin_password), now_iso())
                )

@app.on_event("startup")
def startup():
    init_db()

class SellerRegistration(BaseModel):
    full_name: str = Field(min_length=2, max_length=100)
    store_name: str = Field(min_length=2, max_length=100)
    phone: str = Field(min_length=5, max_length=30)
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)

class LoginInput(BaseModel):
    email: EmailStr
    password: str = Field(min_length=1, max_length=128)

class SellerDecision(BaseModel):
    status: str

class ProductInput(BaseModel):
    name: str = Field(min_length=2, max_length=140)
    description: str = Field(default="", max_length=3000)
    category: str = Field(default="", max_length=80)
    price: float = Field(ge=0, le=100000000)
    stock: int = Field(ge=0, le=10000000)
    image_url: str = Field(default="", max_length=1000)

def public_user(row):
    return {
        "id": row["id"], "email": row["email"], "full_name": row["full_name"],
        "phone": row["phone"], "store_name": row["store_name"],
        "role": row["role"], "status": row["status"], "created_at": row["created_at"]
    }

def issue_session(user_id: int, response: Response):
    token = secrets.token_urlsafe(40)
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    expires = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat()
    with db() as con:
        con.execute("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)",
                    (token_hash, user_id, expires))
    response.set_cookie(
        COOKIE_NAME, token, httponly=True, secure=COOKIE_SECURE,
        samesite="lax", max_age=SESSION_DAYS * 24 * 60 * 60, path="/"
    )

def current_user(request: Request):
    token = request.cookies.get(COOKIE_NAME)
    if not token:
        raise HTTPException(401, "Daxil olun.")
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    with db() as con:
        row = con.execute("""
            SELECT u.*, s.expires_at FROM sessions s
            JOIN users u ON u.id=s.user_id WHERE s.token_hash=?
        """, (token_hash,)).fetchone()
        if not row:
            raise HTTPException(401, "Sessiya tapılmadı. Yenidən daxil olun.")
        if datetime.fromisoformat(row["expires_at"]) < datetime.now(timezone.utc):
            con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
            raise HTTPException(401, "Sessiyanın vaxtı bitib. Yenidən daxil olun.")
        return dict(row)

def require_admin(user=Depends(current_user)):
    if user["role"] != "admin":
        raise HTTPException(403, "Bu əməliyyat yalnız administrator üçündür.")
    return user

def require_approved_seller(user=Depends(current_user)):
    if user["role"] != "seller":
        raise HTTPException(403, "Bu bölmə satıcı hesabı üçündür.")
    if user["status"] != "approved":
        if user["status"] == "rejected":
            raise HTTPException(403, "Satıcı müraciətiniz rədd edilib. Administratorla əlaqə saxlayın.")
        raise HTTPException(403, "Mağazanız hələ təsdiqlənməyib. Administratorun qərarını gözləyin.")
    return user

@app.get("/api/health")
def health():
    return {"ok": True, "service": "ELFA Marketplace API"}

@app.post("/api/auth/register-seller", status_code=201)
def register_seller(data: SellerRegistration):
    email = str(data.email).strip().lower()
    with db() as con:
        if con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone():
            raise HTTPException(409, "Bu e-poçt artıq qeydiyyatdan keçib.")
        con.execute("""
            INSERT INTO users(email,full_name,phone,store_name,password_hash,role,status,created_at)
            VALUES(?,?,?,?,?,'seller','pending',?)
        """, (email, data.full_name.strip(), data.phone.strip(), data.store_name.strip(),
              hash_password(data.password), now_iso()))
        uid = con.execute("SELECT id FROM users WHERE email=?", (email,)).fetchone()["id"]
    return {"ok": True, "user_id": uid, "status": "pending",
            "message": "Qeydiyyat qəbul edildi. Mağazanız administrator təsdiqindən sonra aktivləşəcək."}

@app.post("/api/auth/login")
def login(data: LoginInput, response: Response):
    email = str(data.email).strip().lower()
    with db() as con:
        row = con.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
    if not row or not verify_password(data.password, row["password_hash"]):
        raise HTTPException(401, "E-poçt və ya şifrə yanlışdır.")
    issue_session(row["id"], response)
    return {"ok": True, "user": public_user(row)}

@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    token = request.cookies.get(COOKIE_NAME)
    if token:
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        with db() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?", (token_hash,))
    response.delete_cookie(COOKIE_NAME, path="/", httponly=True, samesite="lax")
    return {"ok": True}

@app.get("/api/auth/me")
def me(user=Depends(current_user)):
    return {"user": {
        "id": user["id"], "email": user["email"], "full_name": user["full_name"],
        "phone": user["phone"], "store_name": user["store_name"],
        "role": user["role"], "status": user["status"]
    }}

@app.get("/api/admin/sellers")
def admin_sellers(user=Depends(require_admin)):
    with db() as con:
        rows = con.execute("""
            SELECT id,email,full_name,phone,store_name,role,status,created_at
            FROM users WHERE role='seller' ORDER BY created_at DESC
        """).fetchall()
    return [public_user(r) for r in rows]

@app.patch("/api/admin/sellers/{seller_id}/decision")
def decide_seller(seller_id: int, data: SellerDecision, user=Depends(require_admin)):
    # Strictly accept only the two explicit administrator decisions.
    status = data.status
    if status not in ("approved", "rejected"):
        raise HTTPException(422, "status 'approved' və ya 'rejected' olmalıdır.")
    with db() as con:
        row = con.execute("SELECT id FROM users WHERE id=? AND role='seller'", (seller_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Satıcı tapılmadı.")
        con.execute("UPDATE users SET status=? WHERE id=?", (status, seller_id))
    return {"ok": True, "seller_id": seller_id, "status": status}

@app.get("/api/seller/products")
def seller_products(user=Depends(require_approved_seller)):
    with db() as con:
        rows = con.execute("""
            SELECT id,name,description,category,price,stock,image_url,active,created_at
            FROM products WHERE seller_id=? ORDER BY created_at DESC
        """, (user["id"],)).fetchall()
    return [dict(r) for r in rows]

@app.post("/api/seller/products", status_code=201)
def create_product(data: ProductInput, user=Depends(require_approved_seller)):
    with db() as con:
        cur = con.execute("""
            INSERT INTO products(seller_id,name,description,category,price,stock,image_url,active,created_at)
            VALUES(?,?,?,?,?,?,?,1,?)
        """, (user["id"], data.name.strip(), data.description.strip(), data.category.strip(),
              data.price, data.stock, data.image_url.strip(), now_iso()))
        pid = cur.lastrowid
    return {"ok": True, "id": pid, "message": "Məhsul əlavə edildi."}

@app.delete("/api/seller/products/{product_id}")
def delete_product(product_id: int, user=Depends(require_approved_seller)):
    with db() as con:
        cur = con.execute("DELETE FROM products WHERE id=? AND seller_id=?", (product_id, user["id"]))
        if cur.rowcount == 0:
            raise HTTPException(404, "Məhsul tapılmadı.")
    return {"ok": True}

@app.get("/api/products")
def public_products():
    with db() as con:
        rows = con.execute("""
            SELECT p.id,p.name,p.description,p.category,p.price,p.stock,p.image_url,u.store_name
            FROM products p JOIN users u ON u.id=p.seller_id
            WHERE p.active=1 AND p.stock>=0 AND u.role='seller' AND u.status='approved'
            ORDER BY p.created_at DESC
        """).fetchall()
    return [dict(r) for r in rows]

# Serve the customer storefront and seller/admin pages after API routes.
app.mount("/", StaticFiles(directory=str(ROOT), html=True), name="site")
