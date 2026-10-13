import hashlib
import hmac
import os
import re
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = os.environ.get("ELFA_DB", str(BASE_DIR / "elfa.db"))
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
SESSION_DAYS = 14

app = FastAPI(title="ELFA API")


# ---------------------------------------------------------------
# Sabit siyahilar (texniki tapshiriqdaki secimler)
# ---------------------------------------------------------------
# Elektronika, Ev ve Yashayish, Ana ve Ushaq kateqoriyalari ataraq daxil edilmeyib.
CATEGORIES = [
    "Geyim", "Ayaqqabı", "Çanta", "Kosmetika",
    "Ətir", "Aksesuar", "Saat", "Eynək", "Digər",
]
GENDERS = ["Qadın", "Kişi", "Uniseks", "Qız", "Oğlan"]
ADULT_GENDERS = ("Qadın", "Kişi", "Uniseks")
KID_GENDERS = ("Qız", "Oğlan")
AGE_GROUPS = ["0-1", "1-3", "4-6", "7-9", "10-12", "13-15", "16-17"]
CLOTHING_SIZES = ["XS", "S", "M", "L", "XL", "XXL"]
SHOE_SIZES = [str(n) for n in range(36, 46)]
COLORS = [
    "Qara", "Ağ", "Qırmızı", "Mavi", "Yaşıl", "Sarı",
    "Çəhrayı", "Boz", "Qəhvəyi", "Bej", "Digər",
]
SIZE_CLASSES = ["Kiçik", "Orta", "Böyük"]

# Bazaya sonradan elave olunan sutunlar (kohne melumatlar silinmir)
SELLER_NEW_COLUMNS = [
    ("logo_url", "TEXT NOT NULL DEFAULT ''"),
    ("whatsapp", "TEXT NOT NULL DEFAULT ''"),
    ("instagram", "TEXT NOT NULL DEFAULT ''"),
    ("tiktok", "TEXT NOT NULL DEFAULT ''"),
    ("address", "TEXT NOT NULL DEFAULT ''"),
]
PRODUCT_NEW_COLUMNS = [
    ("category", "TEXT NOT NULL DEFAULT ''"),
    ("brand", "TEXT NOT NULL DEFAULT ''"),
    ("gender", "TEXT NOT NULL DEFAULT ''"),
    ("age_group", "TEXT NOT NULL DEFAULT ''"),
    ("sizes", "TEXT NOT NULL DEFAULT ''"),
    ("color", "TEXT NOT NULL DEFAULT ''"),
    ("size_class", "TEXT NOT NULL DEFAULT ''"),
    ("dimensions", "TEXT NOT NULL DEFAULT ''"),
    ("material", "TEXT NOT NULL DEFAULT ''"),
]


# Verilenler bazasi
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


def ensure_columns(con, table: str, columns):
    """Cedvelde olmayan sutunlari elave edir. Movcud setirler olduğu kimi qalir."""
    existing = {r["name"] for r in con.execute(f"PRAGMA table_info({table})")}
    for name, ddl in columns:
        if name not in existing:
            con.execute(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}")


def init_db():
    with db() as con:
        con.executescript("""
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
                status TEXT NOT NULL DEFAULT 'pending',
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

            CREATE INDEX IF NOT EXISTS idx_products_seller
            ON products(seller_id);
        """)
        ensure_columns(con, "sellers", SELLER_NEW_COLUMNS)
        ensure_columns(con, "products", PRODUCT_NEW_COLUMNS)


init_db()


# Komekci funksiyalar
def now() -> datetime:
    return datetime.now(timezone.utc)


def hash_password(password: str, salt: Optional[str] = None):
    salt = salt or secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac(
        "sha256", password.encode(), bytes.fromhex(salt), 200_000
    )
    return salt, h.hex()


def sha(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def bearer(authorization: Optional[str]) -> str:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(401, "Giris teleb olunur")
    return authorization[7:].strip()


def current_seller(authorization: Optional[str] = Header(None)) -> sqlite3.Row:
    token = bearer(authorization)
    with db() as con:
        row = con.execute(
            """SELECT s.*, se.expires_at
               FROM sessions se
               JOIN sellers s ON s.id = se.seller_id
               WHERE se.token_hash = ?""",
            (sha(token),),
        ).fetchone()

    if not row:
        raise HTTPException(401, "Sessiya bitib, yeniden daxil olun")

    if datetime.fromisoformat(row["expires_at"]) < now():
        raise HTTPException(401, "Sessiya bitib, yeniden daxil olun")

    return row


def require_admin(authorization: Optional[str] = Header(None)):
    if not ADMIN_TOKEN:
        raise HTTPException(
            503, "Admin girisi sondurulub: ADMIN_TOKEN teyin edilmeyib"
        )
    if not hmac.compare_digest(bearer(authorization), ADMIN_TOKEN):
        raise HTTPException(403, "Icaze yoxdur")


@app.exception_handler(HTTPException)
async def http_exc(_: Request, exc: HTTPException):
    return JSONResponse(
        {"error": exc.detail}, status_code=exc.status_code
    )


@app.exception_handler(RequestValidationError)
async def validation_exc(_: Request, exc: RequestValidationError):
    return JSONResponse(
        {"error": "Gonderilen melumatlar duzgun deyil"},
        status_code=422,
    )


# Melumat modelleri
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
    stock: int = Field(default=0, ge=0, le=1_000_000)
    image_url: str = Field(default="", max_length=500)
    description: str = Field(default="", max_length=600)
    # Yeni sahələr: hamısı ixtiyaridir, köhnə satıcı paneli bunlar olmadan da işləyir
    category: str = Field(default="", max_length=40)
    brand: str = Field(default="", max_length=60)
    gender: str = Field(default="", max_length=20)
    age_group: str = Field(default="", max_length=20)
    sizes: List[str] = Field(default_factory=list, max_length=20)
    color: str = Field(default="", max_length=30)
    size_class: str = Field(default="", max_length=20)
    dimensions: str = Field(default="", max_length=60)
    material: str = Field(default="", max_length=60)


class ProfileIn(BaseModel):
    about: Optional[str] = Field(default=None, max_length=500)
    city: Optional[str] = Field(default=None, max_length=60)
    address: Optional[str] = Field(default=None, max_length=200)
    logo_url: Optional[str] = Field(default=None, max_length=500)
    whatsapp: Optional[str] = Field(default=None, max_length=30)
    instagram: Optional[str] = Field(default=None, max_length=200)
    tiktok: Optional[str] = Field(default=None, max_length=200)


class StatusIn(BaseModel):
    status: str


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^\+994\d{9}$")
HTTP_RE = re.compile(r"^https?://", re.I)
HANDLE_RE = re.compile(r"^[A-Za-z0-9._]{1,60}$")


def fold(s) -> str:
    return (s or "").strip().casefold()


# Yoxlama funksiyalari
def clean_url(value: str, label: str) -> str:
    v = (value or "").strip()
    if v and not HTTP_RE.match(v):
        raise HTTPException(400, f"{label} http(s) ilə başlamalıdır")
    return v


def clean_social(value: str, domain: str, label: str) -> str:
    """Istifadeci ad (@ad) ve ya tam link qebul edir."""
    v = (value or "").strip()
    if not v:
        return ""
    if HTTP_RE.match(v):
        if not re.match(
            r"^https?://([\w-]+\.)*" + re.escape(domain) + r"(/|$)", v, re.I
        ):
            raise HTTPException(400, f"{label} linki {domain} ünvanı olmalıdır")
        return v
    v = v.lstrip("@")
    if not HANDLE_RE.match(v):
        raise HTTPException(400, f"{label} istifadəçi adı düzgün deyil")
    return v


def clean_whatsapp(value: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    digits = re.sub(r"\D", "", v)
    if len(digits) == 9:                       # 501234567
        digits = "994" + digits
    elif len(digits) == 10 and digits.startswith("0"):   # 0501234567
        digits = "994" + digits[1:]
    if not 11 <= len(digits) <= 15:
        raise HTTPException(400, "WhatsApp nömrəsi düzgün deyil")
    return "+" + digits


def clean_product(data: ProductIn) -> dict:
    """Mehsul melumatlarini yoxlayir ve baza ucun hazirlayir."""
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Məhsulun adı boş ola bilməz")

    category = data.category.strip()
    if category and category not in CATEGORIES:
        raise HTTPException(400, "Kateqoriya düzgün deyil")

    gender = data.gender.strip()
    if gender and gender not in GENDERS:
        raise HTTPException(400, "Cinsiyyət düzgün deyil")

    age_group = data.age_group.strip()
    if age_group and age_group not in AGE_GROUPS:
        raise HTTPException(400, "Yaş aralığı düzgün deyil")

    # Qiz/Oglan -> yas var, beden yoxdur. Qadin/Kishi/Uniseks -> beden var, yas yoxdur.
    sizes = []
    for x in data.sizes:
        x = x.strip().upper()
        if x and x not in sizes:
            sizes.append(x)
    if gender in KID_GENDERS:
        sizes = []
    else:
        age_group = ""
        for x in sizes:
            if x not in CLOTHING_SIZES and x not in SHOE_SIZES:
                raise HTTPException(400, "Beden düzgün deyil")
            if category == "Ayaqqabı" and x not in SHOE_SIZES:
                raise HTTPException(400, "Ayaqqabı üçün 36–45 ölçüləri seçilməlidir")
            if category == "Geyim" and x not in CLOTHING_SIZES:
                raise HTTPException(400, "Geyim üçün XS–XXL ölçüləri seçilməlidir")

    color = data.color.strip()
    if color and color not in COLORS:
        raise HTTPException(400, "Rəng düzgün deyil")

    size_class = data.size_class.strip()
    if size_class and size_class not in SIZE_CLASSES:
        raise HTTPException(400, "Boyut düzgün deyil")

    return {
        "name": name,
        "price": data.price,
        "stock": data.stock,
        "image_url": clean_url(data.image_url, "Şəkil linki"),
        "description": data.description.strip(),
        "category": category,
        "brand": data.brand.strip(),
        "gender": gender,
        "age_group": age_group,
        "sizes": ",".join(sizes),
        "color": color,
        "size_class": size_class,
        "dimensions": data.dimensions.strip(),
        "material": data.material.strip(),
    }


PRODUCT_FIELDS = (
    "name", "price", "stock", "image_url", "description", "category",
    "brand", "gender", "age_group", "sizes", "color", "size_class",
    "dimensions", "material",
)


# Satici qeydiyyati
@app.post("/api/sellers/register")
def register(data: RegisterIn):
    email = data.email.strip().lower()

    if not EMAIL_RE.match(email):
        raise HTTPException(400, "E-poct duzgun deyil")

    phone = data.phone.replace(" ", "")

    if not PHONE_RE.match(phone):
        raise HTTPException(400, "Telefon nomresi duzgun deyil")

    salt, pw = hash_password(data.password)

    try:
        with db() as con:
            con.execute(
                """INSERT INTO sellers
                   (store_name, owner_name, category, phone, email,
                    city, about, pw_salt, pw_hash, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (
                    data.store_name.strip(),
                    data.owner_name.strip(),
                    data.category,
                    phone,
                    email,
                    data.city.strip(),
                    data.about.strip(),
                    salt,
                    pw,
                    now().isoformat(),
                ),
            )
    except sqlite3.IntegrityError:
        raise HTTPException(409, "Bu e-poct artiq qeydiyyatdan kecib")

    return {"ok": True, "status": "pending"}


# Satici girisi
@app.post("/api/sellers/login")
def login(data: LoginIn):
    email = data.email.strip().lower()

    with db() as con:
        s = con.execute(
            "SELECT * FROM sellers WHERE email = ?", (email,)
        ).fetchone()

        salt = s["pw_salt"] if s else "00" * 16
        _, hashed = hash_password(data.password, salt)

        if not s or not hmac.compare_digest(hashed, s["pw_hash"]):
            raise HTTPException(401, "E-poct ve ya sifre yanlisdir")

        token = secrets.token_urlsafe(32)

        con.execute(
            """INSERT INTO sessions
               (token_hash, seller_id, expires_at)
               VALUES (?, ?, ?)""",
            (
                sha(token),
                s["id"],
                (now() + timedelta(days=SESSION_DAYS)).isoformat(),
            ),
        )

        con.execute(
            "DELETE FROM sessions WHERE expires_at < ?",
            (now().isoformat(),),
        )

    return {
        "token": token,
        "store_name": s["store_name"],
        "status": s["status"],
    }


@app.post("/api/seller/logout")
def logout(
    authorization: Optional[str] = Header(None),
    s: sqlite3.Row = Depends(current_seller),
):
    with db() as con:
        con.execute(
            "DELETE FROM sessions WHERE token_hash = ?",
            (sha(bearer(authorization)),),
        )
    return {"ok": True}


def seller_private(s: sqlite3.Row) -> dict:
    """Saticinin oz paneli ucun melumatlar (e-poct daxil)."""
    return {
        "store_name": s["store_name"],
        "owner_name": s["owner_name"],
        "email": s["email"],
        "status": s["status"],
        "category": s["category"],
        "phone": s["phone"],
        "city": s["city"],
        "address": s["address"],
        "about": s["about"],
        "logo_url": s["logo_url"],
        "whatsapp": s["whatsapp"],
        "instagram": s["instagram"],
        "tiktok": s["tiktok"],
    }


@app.get("/api/seller/me")
def me(s: sqlite3.Row = Depends(current_seller)):
    return seller_private(s)


@app.put("/api/seller/profile")
def update_profile(
    data: ProfileIn,
    s: sqlite3.Row = Depends(current_seller),
):
    raw = data.model_dump(exclude_unset=True)
    upd = {}

    for key, value in raw.items():
        if value is None:
            continue
        value = value.strip()
        if key == "logo_url":
            value = clean_url(value, "Loqo linki")
        elif key == "whatsapp":
            value = clean_whatsapp(value)
        elif key == "instagram":
            value = clean_social(value, "instagram.com", "Instagram")
        elif key == "tiktok":
            value = clean_social(value, "tiktok.com", "TikTok")
        upd[key] = value

    with db() as con:
        if upd:
            # Acarlar yalniz ProfileIn modelinden gelir, istifadeci yazisi deyil
            sets = ", ".join(f"{k} = ?" for k in upd)
            con.execute(
                f"UPDATE sellers SET {sets} WHERE id = ?",
                (*upd.values(), s["id"]),
            )
        row = con.execute(
            "SELECT * FROM sellers WHERE id = ?", (s["id"],)
        ).fetchone()

    return seller_private(row)


# Mehsullar
def product_dict(r: sqlite3.Row) -> dict:
    keys = r.keys()
    data = {
        k: r[k]
        for k in (
            "id", "name", "price", "stock", "image_url", "description",
            "category", "brand", "gender", "age_group", "color",
            "size_class", "dimensions", "material",
        )
    }
    data["sizes"] = [x for x in (r["sizes"] or "").split(",") if x]

    if "store_name" in keys:
        data["store_name"] = r["store_name"]

    return data


def wa_url(number: str) -> str:
    digits = re.sub(r"\D", "", number or "")
    return f"https://wa.me/{digits}" if digits else ""


def instagram_url(v: str) -> str:
    if not v:
        return ""
    return v if HTTP_RE.match(v) else "https://instagram.com/" + v


def tiktok_url(v: str) -> str:
    if not v:
        return ""
    return v if HTTP_RE.match(v) else "https://www.tiktok.com/@" + v


def public_product_dict(r: sqlite3.Row) -> dict:
    data = product_dict(r)
    data["store_id"] = r["seller_id"]
    data["store_city"] = r["store_city"]
    data["store_phone"] = r["store_phone"]
    data["store_whatsapp_url"] = wa_url(r["store_whatsapp"])
    return data


def public_store_dict(s: sqlite3.Row, product_count: Optional[int] = None) -> dict:
    # E-poct, sahibkarin adi ve sifre melumatlari ictimaiyyete verilmir
    data = {
        "id": s["id"],
        "store_name": s["store_name"],
        "category": s["category"],
        "city": s["city"],
        "address": s["address"],
        "about": s["about"],
        "logo_url": s["logo_url"],
        "phone": s["phone"],
        "whatsapp": s["whatsapp"],
        "whatsapp_url": wa_url(s["whatsapp"]),
        "instagram_url": instagram_url(s["instagram"]),
        "tiktok_url": tiktok_url(s["tiktok"]),
    }
    if product_count is not None:
        data["product_count"] = product_count
    return data


@app.get("/api/seller/products")
def my_products(s: sqlite3.Row = Depends(current_seller)):
    with db() as con:
        rows = con.execute(
            """SELECT * FROM products
               WHERE seller_id = ?
               ORDER BY id DESC""",
            (s["id"],),
        ).fetchall()

    return [product_dict(r) for r in rows]


@app.post("/api/seller/products")
def add_product(
    data: ProductIn,
    s: sqlite3.Row = Depends(current_seller),
):
    f = clean_product(data)

    # Mağaza təsdiq gözləyəndə də məhsul əlavə etmək olar.
    # Məhsul yalnız mağaza təsdiqlənəndən sonra ictimai görünür.
    with db() as con:
        cur = con.execute(
            f"""INSERT INTO products
                (seller_id, {", ".join(PRODUCT_FIELDS)}, created_at)
                VALUES (?, {", ".join("?" for _ in PRODUCT_FIELDS)}, ?)""",
            (s["id"], *[f[k] for k in PRODUCT_FIELDS], now().isoformat()),
        )

        row = con.execute(
            "SELECT * FROM products WHERE id = ?",
            (cur.lastrowid,),
        ).fetchone()

    return product_dict(row)


@app.put("/api/seller/products/{pid}")
def update_product(
    pid: int,
    data: ProductIn,
    s: sqlite3.Row = Depends(current_seller),
):
    """Mehsulu tam yenileyir. Gonderilmeyen sahe boshaldilir, ona gore butun sahəleri gonderin."""
    f = clean_product(data)

    with db() as con:
        cur = con.execute(
            f"""UPDATE products
                SET {", ".join(k + " = ?" for k in PRODUCT_FIELDS)}
                WHERE id = ? AND seller_id = ?""",
            (*[f[k] for k in PRODUCT_FIELDS], pid, s["id"]),
        )

        if cur.rowcount == 0:
            raise HTTPException(404, "Mehsul tapilmadi")

        row = con.execute(
            "SELECT * FROM products WHERE id = ?", (pid,)
        ).fetchone()

    return product_dict(row)


@app.delete("/api/seller/products/{pid}")
def delete_product(
    pid: int,
    s: sqlite3.Row = Depends(current_seller),
):
    with db() as con:
        cur = con.execute(
            "DELETE FROM products WHERE id = ? AND seller_id = ?",
            (pid, s["id"]),
        )

    if cur.rowcount == 0:
        raise HTTPException(404, "Mehsul tapilmadi")

    return {"ok": True}


# Ictimai mehsullar (YALNIZ tesdiqlenmis magazalar)
def approved_rows(con, store_id: Optional[int] = None):
    sql = """SELECT p.*, s.store_name,
                    s.city AS store_city,
                    s.phone AS store_phone,
                    s.whatsapp AS store_whatsapp
             FROM products p
             JOIN sellers s ON s.id = p.seller_id
             WHERE s.status = 'approved'"""
    args = []

    if store_id is not None:
        sql += " AND s.id = ?"
        args.append(store_id)

    sql += " ORDER BY p.id DESC"
    return con.execute(sql, args).fetchall()


@app.get("/api/options")
def options():
    """Satici formasi ve filtr paneli ucun sabit secim siyahilari."""
    return {
        "categories": CATEGORIES,
        "genders": GENDERS,
        "age_groups": AGE_GROUPS,
        "clothing_sizes": CLOTHING_SIZES,
        "shoe_sizes": SHOE_SIZES,
        "colors": COLORS,
        "size_classes": SIZE_CLASSES,
    }


@app.get("/api/filters")
def filters(category: Optional[str] = None):
    """Marka, material ve qiymet aralığı real mehsullardan yaranir."""
    with db() as con:
        rows = approved_rows(con)

    if category:
        rows = [r for r in rows if fold(r["category"]) == fold(category)]

    def distinct(col):
        seen = {}
        for r in rows:
            v = (r[col] or "").strip()
            if v and fold(v) not in seen:
                seen[fold(v)] = v
        return sorted(seen.values(), key=fold)

    prices = [r["price"] for r in rows]

    return {
        "brands": distinct("brand"),
        "materials": distinct("material"),
        "price": {
            "min": min(prices) if prices else None,
            "max": max(prices) if prices else None,
        },
    }


@app.get("/api/products")
def public_products(
    response: Response,
    q: Optional[str] = None,
    category: Optional[str] = None,
    brand: Optional[str] = None,
    gender: Optional[str] = None,
    age: Optional[str] = None,
    size: Optional[str] = None,
    color: Optional[str] = None,
    material: Optional[str] = None,
    size_class: Optional[str] = None,
    price_min: Optional[float] = None,
    price_max: Optional[float] = None,
    store_id: Optional[int] = None,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    with db() as con:
        rows = approved_rows(con, store_id)

    words = fold(q).split() if q else []
    result = []

    for r in rows:
        if category and fold(r["category"]) != fold(category):
            continue
        if brand and fold(r["brand"]) != fold(brand):
            continue
        if gender and fold(r["gender"]) != fold(gender):
            continue
        # Yas melumati olmayan mehsul yas filtrinde cixmir
        if age and (r["age_group"] or "") != age.strip():
            continue
        if size and size.strip().upper() not in (r["sizes"] or "").split(","):
            continue
        if color and fold(r["color"]) != fold(color):
            continue
        if material and fold(r["material"]) != fold(material):
            continue
        if size_class and fold(r["size_class"]) != fold(size_class):
            continue
        if price_min is not None and r["price"] < price_min:
            continue
        if price_max is not None and r["price"] > price_max:
            continue
        if words:
            text = fold(" ".join([
                r["name"], r["brand"], r["store_name"],
                r["category"], r["description"],
            ]))
            if not all(w in text for w in words):
                continue
        result.append(r)

    response.headers["X-Total-Count"] = str(len(result))
    return [public_product_dict(r) for r in result[offset:offset + limit]]


@app.get("/api/products/{pid}")
def public_product(pid: int):
    with db() as con:
        row = next((r for r in approved_rows(con) if r["id"] == pid), None)

    if not row:
        raise HTTPException(404, "Məhsul tapılmadı")

    return public_product_dict(row)


# Ictimai magazalar (YALNIZ tesdiqlenmis)
@app.get("/api/stores")
def public_stores():
    with db() as con:
        stores = con.execute(
            "SELECT * FROM sellers WHERE status = 'approved'"
        ).fetchall()
        counts = {
            r["seller_id"]: r["n"]
            for r in con.execute(
                "SELECT seller_id, COUNT(*) AS n FROM products GROUP BY seller_id"
            )
        }

    stores = sorted(stores, key=lambda s: fold(s["store_name"]))
    return [public_store_dict(s, counts.get(s["id"], 0)) for s in stores]


@app.get("/api/stores/{sid}")
def public_store(sid: int):
    with db() as con:
        s = con.execute(
            "SELECT * FROM sellers WHERE id = ? AND status = 'approved'",
            (sid,),
        ).fetchone()

        if not s:
            raise HTTPException(404, "Mağaza tapılmadı")

        rows = approved_rows(con, sid)

    data = public_store_dict(s, len(rows))
    data["products"] = [public_product_dict(r) for r in rows[:200]]
    return data


# Admin: saticilarin siyahisi
@app.get(
    "/api/admin/sellers",
    dependencies=[Depends(require_admin)],
)
def admin_sellers(status: Optional[str] = None):
    query = """
        SELECT id, store_name, owner_name, category, phone,
               email, city, address, about, whatsapp, instagram,
               tiktok, status, created_at,
               (SELECT COUNT(*) FROM products p
                WHERE p.seller_id = sellers.id) AS product_count
        FROM sellers
    """
    args = ()

    if status:
        query += " WHERE status = ?"
        args = (status,)

    query += " ORDER BY id DESC"

    with db() as con:
        rows = con.execute(query, args).fetchall()

    return [dict(r) for r in rows]


# Admin: satici statusu
@app.post(
    "/api/admin/sellers/{sid}/status",
    dependencies=[Depends(require_admin)],
)
def admin_set_status(sid: int, data: StatusIn):
    if data.status not in ("pending", "approved", "rejected"):
        raise HTTPException(400, "Status yanlisdir")

    with db() as con:
        cur = con.execute(
            "UPDATE sellers SET status = ? WHERE id = ?",
            (data.status, sid),
        )

    if cur.rowcount == 0:
        raise HTTPException(404, "Satici tapilmadi")

    return {"ok": True, "status": data.status}


# Sehifeler
def page(name: str):
    file_path = BASE_DIR / name

    if not file_path.is_file():
        raise HTTPException(404, "Sehife tapilmadi")

    return FileResponse(file_path)


@app.get("/")
@app.get("/elfa.html")
def home():
    return page("index.html")

@app.get("/admin")
def admin_page():
    return page("admin.html")

@app.get("/seller-register.html")
def seller_page():
    return page("seller-register.html")

# Admin: butun magazalarin mehsullarini goster
@app.get(
    "/api/admin/products",
    dependencies=[Depends(require_admin)],
)
def admin_products():
    with db() as con:
        rows = con.execute(
            """SELECT p.*, s.store_name, s.status AS store_status
               FROM products p
               JOIN sellers s ON s.id = p.seller_id
               ORDER BY p.id DESC"""
        ).fetchall()

    result = []
    for r in rows:
        item = product_dict(r)
        item["seller_id"] = r["seller_id"]
        item["created_at"] = r["created_at"]
        item["store_status"] = r["store_status"]
        result.append(item)

    return result


# Admin: mehsulu sil
@app.delete(
    "/api/admin/products/{pid}",
    dependencies=[Depends(require_admin)],
)
def admin_delete_product(pid: int):
    with db() as con:
        cur = con.execute(
            "DELETE FROM products WHERE id = ?",
            (pid,),
        )

    if cur.rowcount == 0:
        raise HTTPException(404, "Mehsul tapilmadi")

    return {"ok": True}

