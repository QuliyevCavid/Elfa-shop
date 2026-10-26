import hashlib
import hmac
import json
import os
import re
import secrets
import time
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List, Optional
from urllib.parse import quote

import psycopg
from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
# Render-də Environment bölməsində DATABASE_URL (Supabase Session pooler linki) təyin edilməlidir.
DATABASE_URL = os.environ.get("DATABASE_URL", "")
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
R2_ACCOUNT_ID = os.environ.get("R2_ACCOUNT_ID", "").strip()
R2_ACCESS_KEY_ID = os.environ.get("R2_ACCESS_KEY_ID", "").strip()
R2_SECRET_ACCESS_KEY = os.environ.get("R2_SECRET_ACCESS_KEY", "").strip()
R2_BUCKET = os.environ.get("R2_BUCKET", "").strip()
R2_PUBLIC_URL = os.environ.get("R2_PUBLIC_URL", "").strip().rstrip("/")
STORAGE_ENABLED = bool(
    R2_ACCOUNT_ID and R2_ACCESS_KEY_ID and R2_SECRET_ACCESS_KEY
    and R2_BUCKET and R2_PUBLIC_URL
)
SESSION_DAYS = 14

app = FastAPI(title="ELFA API")

# ---------------------------------------------------------------
# Sabit siyahılar
# ---------------------------------------------------------------
CATEGORIES = [
    "Geyim", "Ayaqqabı", "Çanta", "Kosmetika",
    "Ətir", "Aksesuar", "Saat", "Eynək", "Digər",
]
GENDERS = ["Qadın", "Kişi", "Uniseks", "Qız", "Oğlan"]
KID_GENDERS = ("Qız", "Oğlan")
AGE_GROUPS = ["0-1", "1-3", "4-6", "7-9", "10-12", "13-15", "16-17"]
CLOTHING_SIZES = ["XS", "S", "M", "L", "XL", "XXL"]
SHOE_SIZES = [str(n) for n in range(36, 46)]
COLORS = [
    "Qara", "Ağ", "Qırmızı", "Mavi", "Yaşıl", "Sarı",
    "Çəhrayı", "Boz", "Qəhvəyi", "Bej", "Digər",
]
SIZE_CLASSES = ["Kiçik", "Orta", "Böyük"]
SELLER_CATEGORIES = [
    "Qadın", "Kişi", "Ana & Uşaq", "Ev & Yaşayış",
    "Kosmetika", "Elektronika", "Digər",
]

SELLER_NEW_COLUMNS = [
    ("logo_url", "TEXT NOT NULL DEFAULT ''"),
    ("whatsapp", "TEXT NOT NULL DEFAULT ''"),
    ("instagram", "TEXT NOT NULL DEFAULT ''"),
    ("tiktok", "TEXT NOT NULL DEFAULT ''"),
    ("address", "TEXT NOT NULL DEFAULT ''"),
    ("home_slots", "INTEGER NOT NULL DEFAULT 0"),
    ("home_all", "INTEGER NOT NULL DEFAULT 0"),
]
PRODUCT_NEW_COLUMNS = [
    ("on_home", "INTEGER NOT NULL DEFAULT 0"),
    ("video_url", "TEXT NOT NULL DEFAULT ''"),
    ("category", "TEXT NOT NULL DEFAULT ''"),
    ("brand", "TEXT NOT NULL DEFAULT ''"),
    ("gender", "TEXT NOT NULL DEFAULT ''"),
    ("age_group", "TEXT NOT NULL DEFAULT ''"),
    ("sizes", "TEXT NOT NULL DEFAULT ''"),
    ("color", "TEXT NOT NULL DEFAULT ''"),
    ("size_class", "TEXT NOT NULL DEFAULT ''"),
    ("dimensions", "TEXT NOT NULL DEFAULT ''"),
    ("material", "TEXT NOT NULL DEFAULT ''"),
    ("images", "TEXT NOT NULL DEFAULT ''"),
]


# ---------------------------------------------------------------
# Verilənlər bazası (Supabase Postgres)
# ---------------------------------------------------------------
class Row(dict):
    """Həm row["ad"], həm row[0] işləyir."""

    def __getitem__(self, k):
        if isinstance(k, int):
            return list(self.values())[k]
        return super().__getitem__(k)


def row_factory(cursor):
    cols = [c.name for c in cursor.description] if cursor.description else []

    def make(values):
        return Row(zip(cols, values))

    return make


class Conn:
    def __init__(self, raw):
        self.raw = raw

    def execute(self, sql, params=None):
        if params:
            return self.raw.execute(sql.replace("?", "%s"), params)
        return self.raw.execute(sql)


@contextmanager
def db():
    raw = psycopg.connect(
        DATABASE_URL,
        row_factory=row_factory,
        prepare_threshold=None,
        connect_timeout=15,
    )
    try:
        yield Conn(raw)
        raw.commit()
    finally:
        raw.close()


def ensure_columns(con, table: str, columns):
    for name, ddl in columns:
        con.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {name} {ddl}")


def init_db():
    with db() as con:
        con.execute("""
            CREATE TABLE IF NOT EXISTS sellers (
                id SERIAL PRIMARY KEY,
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
                id SERIAL PRIMARY KEY,
                seller_id INTEGER NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
                name TEXT NOT NULL,
                price DOUBLE PRECISION NOT NULL,
                stock INTEGER NOT NULL,
                image_url TEXT DEFAULT '',
                description TEXT DEFAULT '',
                created_at TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_products_seller ON products(seller_id);
            CREATE TABLE IF NOT EXISTS images (
                id SERIAL PRIMARY KEY,
                seller_id INTEGER NOT NULL REFERENCES sellers(id) ON DELETE CASCADE,
                mime TEXT NOT NULL,
                data BYTEA NOT NULL,
                created_at TEXT NOT NULL
            );
        """)
        ensure_columns(con, "sellers", SELLER_NEW_COLUMNS)
        ensure_columns(con, "products", PRODUCT_NEW_COLUMNS)


init_db()


# ---------------------------------------------------------------
# Köməkçi funksiyalar
# ---------------------------------------------------------------
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


# Sadə sorğu limiti (şifrə təxmin hücumuna qarşı). Bir proses üçün işləyir.
_FAILS: dict = {}
MAX_FAILS = 10
FAIL_WINDOW = 300


def _recent(key: str) -> list:
    t = time.time()
    lst = [x for x in _FAILS.get(key, []) if t - x < FAIL_WINDOW]
    _FAILS[key] = lst
    return lst


def check_blocked(key: str):
    if len(_recent(key)) >= MAX_FAILS:
        raise HTTPException(429, "Çox sayda uğursuz cəhd. 5 dəqiqə sonra yenidən yoxlayın")


def add_fail(key: str):
    _recent(key).append(time.time())


def client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else "?"


def current_seller(authorization: Optional[str] = Header(None)) -> Row:
    token = bearer(authorization)
    with db() as con:
        row = con.execute(
            """SELECT s.*, se.expires_at
               FROM sessions se JOIN sellers s ON s.id = se.seller_id
               WHERE se.token_hash = ?""",
            (sha(token),),
        ).fetchone()
    if not row or datetime.fromisoformat(row["expires_at"]) < now():
        raise HTTPException(401, "Sessiya bitib, yenidən daxil olun")
    return row


def require_admin(request: Request, authorization: Optional[str] = Header(None)):
    if not ADMIN_TOKEN:
        raise HTTPException(503, "Admin girişi söndürülüb: ADMIN_TOKEN təyin edilməyib")
    key = "admin:" + client_ip(request)
    check_blocked(key)
    if not hmac.compare_digest(bearer(authorization), ADMIN_TOKEN):
        add_fail(key)
        raise HTTPException(403, "İcazə yoxdur")


@app.exception_handler(HTTPException)
async def http_exc(_: Request, exc: HTTPException):
    return JSONResponse({"error": exc.detail}, status_code=exc.status_code)


FIELD_LABELS = {
    "store_name": "Mağaza adı", "owner_name": "Ad və soyad", "category": "Kateqoriya",
    "phone": "Telefon", "email": "E-poçt", "password": "Şifrə", "city": "Şəhər",
    "about": "Haqqında", "name": "Məhsulun adı", "price": "Qiymət", "stock": "Stok",
    "image_url": "Şəkil linki", "images": "Şəkillər", "description": "Təsvir", "brand": "Marka",
    "dimensions": "Ölçülər", "material": "Material", "address": "Ünvan",
    "whatsapp": "WhatsApp", "instagram": "Instagram", "tiktok": "TikTok",
}


@app.exception_handler(RequestValidationError)
async def validation_exc(_: Request, exc: RequestValidationError):
    errs = exc.errors()
    if not errs:
        return JSONResponse({"error": "Göndərilən məlumatlar düzgün deyil"}, status_code=422)
    e = errs[0]
    field = str(e["loc"][-1]) if e.get("loc") else ""
    label = FIELD_LABELS.get(field, field or "Sahə")
    kind = e.get("type", "")
    if kind == "missing":
        msg = f"“{label}” sahəsi boş ola bilməz"
    elif "too_short" in kind or "min_length" in kind:
        msg = f"“{label}” çox qısadır"
    elif "too_long" in kind or "max_length" in kind:
        msg = f"“{label}” çox uzundur"
    else:
        msg = f"“{label}” sahəsi düzgün deyil"
    return JSONResponse({"error": msg}, status_code=422)


# ---------------------------------------------------------------
# Modellər
# ---------------------------------------------------------------
class RegisterIn(BaseModel):
    store_name: str = Field(min_length=2, max_length=40)
    owner_name: str = Field(min_length=2, max_length=80)
    category: str = Field(default="Digər", max_length=40)
    phone: str = Field(max_length=30)
    email: str = Field(max_length=120)
    password: str = Field(max_length=100)
    city: str = Field(default="", max_length=120)
    about: str = Field(default="", max_length=500)


class LoginIn(BaseModel):
    email: str = Field(max_length=120)
    password: str = Field(max_length=100)


class ProductIn(BaseModel):
    name: str = Field(min_length=1, max_length=80)
    price: float = Field(ge=0, le=1_000_000)
    stock: int = Field(default=0, ge=0, le=1_000_000)
    image_url: str = Field(default="", max_length=500)
    images: List[str] = Field(default_factory=list, max_length=5)
    description: str = Field(default="", max_length=600)
    category: str = Field(default="", max_length=60)
    brand: str = Field(default="", max_length=60)
    gender: str = Field(default="", max_length=20)
    age_group: str = Field(default="", max_length=20)
    sizes: List[str] = Field(default_factory=list, max_length=20)
    color: str = Field(default="", max_length=40)
    size_class: str = Field(default="", max_length=40)
    dimensions: str = Field(default="", max_length=60)
    material: str = Field(default="", max_length=60)
    video_url: str = Field(default="", max_length=500)


class ProfileIn(BaseModel):
    about: Optional[str] = Field(default=None, max_length=500)
    city: Optional[str] = Field(default=None, max_length=120)
    address: Optional[str] = Field(default=None, max_length=200)
    logo_url: Optional[str] = Field(default=None, max_length=500)
    whatsapp: Optional[str] = Field(default=None, max_length=30)
    instagram: Optional[str] = Field(default=None, max_length=200)
    tiktok: Optional[str] = Field(default=None, max_length=200)


class StatusIn(BaseModel):
    status: str


class HomeIn(BaseModel):
    on_home: bool


class SellerHomeIn(BaseModel):
    slots: Optional[int] = Field(default=None, ge=0, le=1000)
    all: Optional[bool] = None


EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
HTTP_RE = re.compile(r"^https?://", re.I)
HANDLE_RE = re.compile(r"^[A-Za-z0-9._]{1,60}$")
IMG_PATH_RE = re.compile(r"^/api/images/(\d+)$")

# Azərbaycan hərflərini və diakritikləri sadələşdirir: "İpək", "ipek", "IPEK" eyni sayılır
_AZ = str.maketrans({
    "İ": "i", "I": "i", "ı": "i",
    "Ə": "e", "ə": "e", "Ö": "o", "ö": "o", "Ü": "u", "ü": "u",
    "Ş": "s", "ş": "s", "Ç": "c", "ç": "c", "Ğ": "g", "ğ": "g",
})


def fold(s) -> str:
    return (s or "").strip().translate(_AZ).casefold()


# ---------------------------------------------------------------
# Yoxlama funksiyaları
# ---------------------------------------------------------------
def clean_url(value: str, label: str) -> str:
    v = (value or "").strip()
    if v and not HTTP_RE.match(v):
        raise HTTPException(400, f"{label} http(s) ilə başlamalıdır")
    return v


def clean_image_url(value: str, label: str) -> str:
    v = (value or "").strip()
    if v and IMG_PATH_RE.match(v):
        return v
    return clean_url(v, label)


def clean_social(value: str, domain: str, label: str) -> str:
    v = (value or "").strip()
    if not v:
        return ""
    if HTTP_RE.match(v):
        if not re.match(r"^https?://([\w-]+\.)*" + re.escape(domain) + r"(/|$)", v, re.I):
            raise HTTPException(400, f"{label} linki {domain} ünvanı olmalıdır")
        return v
    v = v.lstrip("@")
    if not HANDLE_RE.match(v):
        raise HTTPException(400, f"{label} istifadəçi adı düzgün deyil")
    return v


def normalize_az_number(value: str) -> Optional[str]:
    """050 123 45 67 / 0501234567 / 501234567 / +994501234567 -> 994501234567"""
    digits = re.sub(r"\D", "", value or "")
    if len(digits) == 9:
        digits = "994" + digits
    elif len(digits) == 10 and digits.startswith("0"):
        digits = "994" + digits[1:]
    return digits if re.fullmatch(r"994\d{9}", digits) else None


def clean_phone(value: str) -> str:
    d = normalize_az_number(value)
    if not d:
        raise HTTPException(400, "Telefon nömrəsi düzgün deyil (məs: 050 123 45 67)")
    return "+" + d


def check_password(pw: str):
    """Düz 11 simvol: 8 rəqəm + 1 böyük hərf + 1 kiçik hərf + 1 simvol (boşluq olmaz)."""
    digits = sum(c in "0123456789" for c in pw)
    ok = (
        len(pw) == 11
        and not any(c.isspace() for c in pw)
        and digits >= 8
        and any(c.isupper() for c in pw)
        and any(c.islower() for c in pw)
        and any(not c.isalnum() for c in pw)
    )
    if not ok:
        raise HTTPException(
            400,
            "Şifrə düz 11 simvol olmalıdır: 8 rəqəm, 1 böyük hərf, 1 kiçik hərf və 1 simvol (məs: 12345678Aa!)",
        )


def clean_whatsapp(value: str) -> str:
    """Yalnız Azərbaycan nömrəsi: 9 rəqəm (məs: 501234567) -> +994501234567"""
    v = (value or "").strip()
    if not v:
        return ""
    d = normalize_az_number(v)
    if not d:
        raise HTTPException(400, "WhatsApp nömrəsi 9 rəqəm olmalıdır (məs: 501234567)")
    return "+" + d


VIDEO_HOSTS = {
    "youtube.com", "www.youtube.com", "m.youtube.com", "youtu.be",
    "vimeo.com", "www.vimeo.com", "player.vimeo.com",
}
VIDEO_FILE_RE = re.compile(r"^https://[^\s]+\.(mp4|webm|mov|m4v)(\?[^\s]*)?$", re.I)


def clean_video_url(value: str, seller_id: int) -> str:
    """Qəbul olunur: satıcının öz R2 videosu, YouTube/Vimeo linki və ya birbaşa .mp4/.webm/.mov linki."""
    v = (value or "").strip()
    if not v:
        return ""
    if len(v) > 500:
        raise HTTPException(400, "Video linki çox uzundur")
    if STORAGE_ENABLED and v.startswith(f"{R2_PUBLIC_URL}/seller_{seller_id}/"):
        return v
    m = re.match(r"^https://([^/\s?#]+)(/[^\s]*)?$", v, re.I)
    if m and m.group(1).lower() in VIDEO_HOSTS:
        return v
    if VIDEO_FILE_RE.match(v):
        return v
    raise HTTPException(400, "Video linki düzgün deyil. YouTube, Vimeo və ya .mp4 linki yazın")


def clean_product(data: ProductIn, seller_id: int) -> dict:
    name = data.name.strip()
    if not name:
        raise HTTPException(400, "Məhsulun adı boş ola bilməz")

    category = data.category.strip()  # siyahıdan və ya satıcının özü yazdığı kateqoriya

    gender = data.gender.strip()
    if gender and gender not in GENDERS:
        raise HTTPException(400, "Cinsiyyət düzgün deyil")

    age_group = data.age_group.strip()
    if age_group and age_group not in AGE_GROUPS:
        raise HTTPException(400, "Yaş aralığı düzgün deyil")

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
            if len(x) > 20:
                raise HTTPException(400, "Bədən ölçüsü çox uzundur")

    color = data.color.strip()

    size_class = data.size_class.strip()

    images = []
    for u in data.images:
        u = clean_image_url(u, "Şəkil linki")
        if len(u) > 500:
            raise HTTPException(400, "Şəkil linki çox uzundur")
        if u and u not in images:
            images.append(u)
    if not images and data.image_url.strip():
        images = [clean_image_url(data.image_url, "Şəkil linki")]
    images = images[:5]

    return {
        "name": name,
        "price": data.price,
        "stock": data.stock,
        "image_url": images[0] if images else "",
        "images": json.dumps(images),
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
        "video_url": clean_video_url(data.video_url, seller_id),
    }


PRODUCT_FIELDS = (
    "name", "price", "stock", "image_url", "images", "description", "category",
    "brand", "gender", "age_group", "sizes", "color", "size_class",
    "dimensions", "material", "video_url",
)


def row_image_urls(row) -> set:
    """Məhsul sətrindəki bütün şəkil linkləri (əsas + əlavə)."""
    urls = set()
    if row["image_url"]:
        urls.add(row["image_url"])
    try:
        for u in json.loads(row["images"] or "[]"):
            if isinstance(u, str) and u:
                urls.add(u)
    except ValueError:
        pass
    return urls


def drop_image(con, seller_id: int, url: str):
    """Serverdə saxlanmış şəkil artıq istifadə olunmursa bazadan silir (limit dolmasın)."""
    m = IMG_PATH_RE.match(url or "")
    if not m:
        return
    iid = int(m.group(1))
    used = con.execute(
        """SELECT (SELECT COUNT(*) FROM products WHERE image_url = ? OR images LIKE ?)
                + (SELECT COUNT(*) FROM sellers WHERE logo_url = ?)""",
        (url, '%' + json.dumps(url) + '%', url),
    ).fetchone()[0]
    if used == 0:
        con.execute("DELETE FROM images WHERE id = ? AND seller_id = ?", (iid, seller_id))


# ---------------------------------------------------------------
# Satıcı qeydiyyatı və girişi
# ---------------------------------------------------------------
@app.post("/api/sellers/register")
def register(data: RegisterIn):
    email = data.email.strip().lower()
    if not EMAIL_RE.match(email):
        raise HTTPException(400, "E-poçt düzgün deyil")

    phone = clean_phone(data.phone)
    store_name = data.store_name.strip()
    owner_name = data.owner_name.strip()
    if len(store_name) < 2:
        raise HTTPException(400, "Mağaza adı ən azı 2 hərf olmalıdır")
    if len(owner_name) < 2:
        raise HTTPException(400, "Ad və soyad ən azı 2 hərf olmalıdır")
    category = (data.category or "").strip() or "Digər"
    if category not in SELLER_CATEGORIES:
        raise HTTPException(400, "Kateqoriya düzgün deyil")

    check_password(data.password)
    salt, pw = hash_password(data.password)
    try:
        with db() as con:
            con.execute(
                """INSERT INTO sellers
                   (store_name, owner_name, category, phone, email,
                    city, about, pw_salt, pw_hash, status, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending', ?)""",
                (store_name, owner_name, category, phone, email,
                 data.city.strip(), data.about.strip(), salt, pw, now().isoformat()),
            )
    except psycopg.errors.UniqueViolation:
        raise HTTPException(409, "Bu e-poçt artıq qeydiyyatdan keçib")
    return {"ok": True, "status": "pending"}


@app.post("/api/sellers/login")
def login(data: LoginIn, request: Request):
    email = data.email.strip().lower()
    key = f"login:{client_ip(request)}:{email}"
    check_blocked(key)

    with db() as con:
        s = con.execute("SELECT * FROM sellers WHERE email = ?", (email,)).fetchone()
        salt = s["pw_salt"] if s else "00" * 16
        _, hashed = hash_password(data.password, salt)

        if not s or not hmac.compare_digest(hashed, s["pw_hash"]):
            add_fail(key)
            raise HTTPException(401, "E-poçt və ya şifrə yanlışdır")

        token = secrets.token_urlsafe(32)
        con.execute(
            "INSERT INTO sessions (token_hash, seller_id, expires_at) VALUES (?, ?, ?)",
            (sha(token), s["id"], (now() + timedelta(days=SESSION_DAYS)).isoformat()),
        )
        con.execute("DELETE FROM sessions WHERE expires_at < ?", (now().isoformat(),))

    _FAILS.pop(key, None)
    return {"token": token, "store_name": s["store_name"], "status": s["status"]}


@app.post("/api/seller/logout")
def logout(
    authorization: Optional[str] = Header(None),
    s: Row = Depends(current_seller),
):
    with db() as con:
        con.execute("DELETE FROM sessions WHERE token_hash = ?", (sha(bearer(authorization)),))
    return {"ok": True}


def home_used(con, seller_id: int) -> int:
    return con.execute(
        "SELECT COUNT(*) FROM products WHERE seller_id = ? AND on_home = 1",
        (seller_id,),
    ).fetchone()[0]


def seller_private(s: Row, used: int = 0) -> dict:
    return {
        "home_slots": s["home_slots"],
        "home_used": used,
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
def me(s: Row = Depends(current_seller)):
    with db() as con:
        used = home_used(con, s["id"])
    return seller_private(s, used)


@app.put("/api/seller/profile")
def update_profile(data: ProfileIn, s: Row = Depends(current_seller)):
    raw = data.model_dump(exclude_unset=True)
    upd = {}
    for key, value in raw.items():
        if value is None:
            continue
        value = value.strip()
        if key == "logo_url":
            value = clean_image_url(value, "Loqo linki")
        elif key == "whatsapp":
            value = clean_whatsapp(value)
        elif key == "instagram":
            value = clean_social(value, "instagram.com", "Instagram")
        elif key == "tiktok":
            value = clean_social(value, "tiktok.com", "TikTok")
        upd[key] = value

    with db() as con:
        old_logo = s["logo_url"]
        if upd:
            sets = ", ".join(f"{k} = ?" for k in upd)  # açarlar yalnız ProfileIn-dən gəlir
            con.execute(f"UPDATE sellers SET {sets} WHERE id = ?", (*upd.values(), s["id"]))
            if "logo_url" in upd and upd["logo_url"] != old_logo:
                drop_image(con, s["id"], old_logo)
        row = con.execute("SELECT * FROM sellers WHERE id = ?", (s["id"],)).fetchone()
        used = home_used(con, s["id"])
    return seller_private(row, used)


# ---------------------------------------------------------------
# Şəkil yükləmə
# ---------------------------------------------------------------
MAX_IMAGE_BYTES = 3 * 1024 * 1024
MAX_IMAGES_PER_SELLER = 300


def sniff_image(b: bytes) -> Optional[str]:
    if b.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if b.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if b[:4] == b"RIFF" and b[8:12] == b"WEBP":
        return "image/webp"
    return None


@app.post("/api/seller/upload")
async def upload_image(request: Request, s: Row = Depends(current_seller)):
    declared = request.headers.get("content-length")
    if declared and declared.isdigit() and int(declared) > MAX_IMAGE_BYTES:
        raise HTTPException(413, "Şəkil çox böyükdür (maksimum 3 MB)")

    body = await request.body()
    if not body:
        raise HTTPException(400, "Şəkil boşdur")
    if len(body) > MAX_IMAGE_BYTES:
        raise HTTPException(413, "Şəkil çox böyükdür (maksimum 3 MB)")

    mime = sniff_image(body)
    if not mime:
        raise HTTPException(400, "Yalnız JPG, PNG və ya WEBP şəkil yüklənə bilər")

    with db() as con:
        n = con.execute("SELECT COUNT(*) FROM images WHERE seller_id = ?", (s["id"],)).fetchone()[0]
        if n >= MAX_IMAGES_PER_SELLER:
            raise HTTPException(400, "Şəkil limiti doldu. Lazımsız məhsulları silin")
        cur = con.execute(
            "INSERT INTO images (seller_id, mime, data, created_at) VALUES (?, ?, ?, ?) RETURNING id",
            (s["id"], mime, body, now().isoformat()),
        )
        new_id = cur.fetchone()["id"]
    return {"url": f"/api/images/{new_id}"}


def sigv4_presign(
    method: str, host: str, path: str, access_key: str, secret: str,
    region: str, service: str, when: datetime, expires: int, content_type: str,
) -> str:
    """AWS SigV4 ilə imzalanmış link. 'content-type' və 'host' başlıqları imzalanır."""
    amz_date = when.strftime("%Y%m%dT%H%M%SZ")
    day = when.strftime("%Y%m%d")
    scope = f"{day}/{region}/{service}/aws4_request"
    enc = lambda x: quote(x, safe="-_.~")

    params = {
        "X-Amz-Algorithm": "AWS4-HMAC-SHA256",
        "X-Amz-Credential": f"{access_key}/{scope}",
        "X-Amz-Date": amz_date,
        "X-Amz-Expires": str(expires),
        "X-Amz-SignedHeaders": "content-type;host",
    }
    canonical_qs = "&".join(f"{enc(k)}={enc(v)}" for k, v in sorted(params.items()))
    canonical_request = "\n".join([
        method, path, canonical_qs,
        f"content-type:{content_type}\nhost:{host}\n",
        "content-type;host", "UNSIGNED-PAYLOAD",
    ])
    string_to_sign = "\n".join([
        "AWS4-HMAC-SHA256", amz_date, scope,
        hashlib.sha256(canonical_request.encode()).hexdigest(),
    ])

    def h(key: bytes, msg: str) -> bytes:
        return hmac.new(key, msg.encode(), hashlib.sha256).digest()

    k = h(("AWS4" + secret).encode(), day)
    k = h(k, region)
    k = h(k, service)
    k = h(k, "aws4_request")
    signature = hmac.new(k, string_to_sign.encode(), hashlib.sha256).hexdigest()
    return f"https://{host}{path}?{canonical_qs}&X-Amz-Signature={signature}"


UPLOAD_TYPES = {
    "image": {"image/jpeg": "jpg", "image/png": "png", "image/webp": "webp"},
    "video": {
        "video/mp4": "mp4", "video/quicktime": "mov",
        "video/webm": "webm", "video/x-m4v": "m4v",
    },
}


class UploadUrlIn(BaseModel):
    kind: str
    content_type: str


@app.post("/api/seller/upload-url")
def upload_url(data: UploadUrlIn, s: Row = Depends(current_seller)):
    if not STORAGE_ENABLED:
        raise HTTPException(503, "Fayl yükləmə hələ aktiv edilməyib")
    if s["status"] != "approved":
        raise HTTPException(403, "Mağazanız təsdiqlənəndən sonra yükləmək olar")

    ctype = data.content_type.strip().lower()
    exts = UPLOAD_TYPES.get(data.kind)
    ext = exts.get(ctype) if exts else None
    if not ext:
        raise HTTPException(400, "Bu fayl növü dəstəklənmir")

    key = f"seller_{s['id']}/{int(time.time())}_{secrets.token_hex(6)}.{ext}"
    host = f"{R2_ACCOUNT_ID}.r2.cloudflarestorage.com"
    path = f"/{R2_BUCKET}/{quote(key, safe='/-_.~')}"
    url = sigv4_presign(
        "PUT", host, path, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY,
        "auto", "s3", now(), 3600, ctype,
    )
    return {"upload_url": url, "public_url": f"{R2_PUBLIC_URL}/{key}"}


@app.get("/api/images/{iid}")
def get_image(iid: int, request: Request):
    with db() as con:
        row = con.execute("SELECT mime, data FROM images WHERE id = ?", (iid,)).fetchone()
    if not row:
        raise HTTPException(404, "Şəkil tapılmadı")
    data = bytes(row["data"])
    etag = '"' + hashlib.sha256(data).hexdigest()[:32] + '"'
    headers = {"ETag": etag, "Cache-Control": "no-cache", "X-Content-Type-Options": "nosniff"}
    if request.headers.get("if-none-match") == etag:
        return Response(status_code=304, headers=headers)
    return Response(content=data, media_type=row["mime"], headers=headers)


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return Response(status_code=204)


# ---------------------------------------------------------------
# Məhsullar
# ---------------------------------------------------------------
def product_dict(r: Row) -> dict:
    keys = r.keys()
    data = {
        k: r[k]
        for k in (
            "id", "name", "price", "stock", "image_url", "description",
            "category", "brand", "gender", "age_group", "color",
            "size_class", "dimensions", "material", "video_url",
        )
    }
    data["sizes"] = [x for x in (r["sizes"] or "").split(",") if x]
    imgs = []
    if "images" in keys:
        try:
            imgs = [u for u in json.loads(r["images"] or "[]") if isinstance(u, str) and u]
        except ValueError:
            imgs = []
    if not imgs and r["image_url"]:
        imgs = [r["image_url"]]
    data["images"] = imgs
    data["on_home"] = bool(r["on_home"])
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


def public_product_dict(r: Row) -> dict:
    data = product_dict(r)
    data["store_id"] = r["seller_id"]
    data["store_city"] = r["store_city"]
    data["store_category"] = r["store_category"]
    data["store_phone"] = r["store_phone"]
    # Mağazanın WhatsApp nömrəsi yoxdursa, telefon nömrəsi ilə WhatsApp linki düzəlir
    data["store_whatsapp_url"] = wa_url(r["store_whatsapp"] or r["store_phone"])
    return data


def public_store_dict(s: Row, product_count: Optional[int] = None) -> dict:
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
        "whatsapp_url": wa_url(s["whatsapp"] or s["phone"]),
        "instagram_url": instagram_url(s["instagram"]),
        "tiktok_url": tiktok_url(s["tiktok"]),
    }
    if product_count is not None:
        data["product_count"] = product_count
    return data


@app.get("/api/seller/products")
def my_products(s: Row = Depends(current_seller)):
    with db() as con:
        rows = con.execute(
            "SELECT * FROM products WHERE seller_id = ? ORDER BY id DESC", (s["id"],)
        ).fetchall()
    return [product_dict(r) for r in rows]


@app.post("/api/seller/products")
def add_product(data: ProductIn, s: Row = Depends(current_seller)):
    if s["status"] == "rejected":
        raise HTTPException(403, "Mağazanız rədd edilib, məhsul əlavə etmək olmaz")
    f = clean_product(data, s["id"])
    # Təsdiq gözləyən mağaza da məhsul əlavə edə bilər; məhsul yalnız təsdiqdən sonra ictimai görünür.
    with db() as con:
        cur = con.execute(
            f"""INSERT INTO products
                (seller_id, {", ".join(PRODUCT_FIELDS)}, created_at)
                VALUES (?, {", ".join("?" for _ in PRODUCT_FIELDS)}, ?)
                RETURNING id""",
            (s["id"], *[f[k] for k in PRODUCT_FIELDS], now().isoformat()),
        )
        new_id = cur.fetchone()["id"]
        row = con.execute("SELECT * FROM products WHERE id = ?", (new_id,)).fetchone()
    return product_dict(row)


@app.put("/api/seller/products/{pid}/home")
def seller_set_home(pid: int, data: HomeIn, s: Row = Depends(current_seller)):
    with db() as con:
        p = con.execute(
            "SELECT id, on_home FROM products WHERE id = ? AND seller_id = ?",
            (pid, s["id"]),
        ).fetchone()
        if not p:
            raise HTTPException(404, "Məhsul tapılmadı")

        if data.on_home and not p["on_home"]:
            used = home_used(con, s["id"])
            if used >= s["home_slots"]:
                raise HTTPException(400, f"Ana səhifə limitiniz dolub ({used}/{s['home_slots']})")

        con.execute("UPDATE products SET on_home = ? WHERE id = ?", (1 if data.on_home else 0, pid))
        used = home_used(con, s["id"])
    return {"ok": True, "on_home": data.on_home, "home_used": used, "home_slots": s["home_slots"]}


@app.put("/api/seller/products/{pid}")
def update_product(pid: int, data: ProductIn, s: Row = Depends(current_seller)):
    """Məhsulu tam yeniləyir. Göndərilməyən sahə boşaldılır, ona görə bütün sahələri göndərin.
    'on_home' bu sorğu ilə dəyişmir."""
    if s["status"] == "rejected":
        raise HTTPException(403, "Mağazanız rədd edilib")
    f = clean_product(data, s["id"])
    with db() as con:
        old = con.execute(
            "SELECT image_url, images FROM products WHERE id = ? AND seller_id = ?", (pid, s["id"])
        ).fetchone()
        if not old:
            raise HTTPException(404, "Məhsul tapılmadı")
        con.execute(
            f"""UPDATE products SET {", ".join(k + " = ?" for k in PRODUCT_FIELDS)}
                WHERE id = ? AND seller_id = ?""",
            (*[f[k] for k in PRODUCT_FIELDS], pid, s["id"]),
        )
        new_urls = {f["image_url"], *json.loads(f["images"])}
        for u in row_image_urls(old) - new_urls:
            drop_image(con, s["id"], u)
        row = con.execute("SELECT * FROM products WHERE id = ?", (pid,)).fetchone()
    return product_dict(row)


@app.delete("/api/seller/products/{pid}")
def delete_product(pid: int, s: Row = Depends(current_seller)):
    with db() as con:
        old = con.execute(
            "SELECT image_url, images FROM products WHERE id = ? AND seller_id = ?", (pid, s["id"])
        ).fetchone()
        if not old:
            raise HTTPException(404, "Məhsul tapılmadı")
        con.execute("DELETE FROM products WHERE id = ? AND seller_id = ?", (pid, s["id"]))
        for u in row_image_urls(old):
            drop_image(con, s["id"], u)
    return {"ok": True}


# ---------------------------------------------------------------
# İctimai məhsullar (yalnız təsdiqlənmiş mağazalar)
# ---------------------------------------------------------------
def approved_rows(con, store_id: Optional[int] = None, product_id: Optional[int] = None):
    sql = """SELECT p.*, s.store_name,
                    s.home_all AS store_home_all,
                    s.category AS store_category,
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
    if product_id is not None:
        sql += " AND p.id = ?"
        args.append(product_id)
    sql += " ORDER BY p.id DESC"
    return con.execute(sql, args).fetchall()


@app.get("/api/options")
def options():
    return {
        "categories": CATEGORIES,
        "genders": GENDERS,
        "age_groups": AGE_GROUPS,
        "clothing_sizes": CLOTHING_SIZES,
        "shoe_sizes": SHOE_SIZES,
        "colors": COLORS,
        "size_classes": SIZE_CLASSES,
        "storage_enabled": STORAGE_ENABLED,
    }


@app.get("/api/filters")
def filters(category: Optional[str] = None):
    with db() as con:
        all_rows = approved_rows(con)
    rows = all_rows
    if category:
        rows = [r for r in rows if fold(r["category"]) == fold(category)]

    def distinct(col, src=None):
        seen = {}
        for r in (rows if src is None else src):
            v = (r[col] or "").strip()
            if v and fold(v) not in seen:
                seen[fold(v)] = v
        return sorted(seen.values(), key=fold)

    prices = [r["price"] for r in rows]
    return {
        "brands": distinct("brand"),
        "materials": distinct("material"),
        # bütün (süzülməmiş) kateqoriyalar: satıcıların özü yazdıqları da daxildir
        "categories": distinct("category", all_rows),
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
    store_category: Optional[str] = None,
    home: Optional[bool] = None,
    sort: Optional[str] = None,
    limit: int = Query(100, ge=1, le=200),
    offset: int = Query(0, ge=0),
):
    with db() as con:
        rows = approved_rows(con, store_id)

    words = fold(q).split() if q else []
    result = []
    for r in rows:
        if home and not (r["on_home"] or r["store_home_all"]):
            continue
        if category and fold(r["category"]) != fold(category):
            continue
        if store_category and fold(r["store_category"]) != fold(store_category):
            continue
        if brand and fold(r["brand"]) != fold(brand):
            continue
        if gender and fold(r["gender"]) != fold(gender):
            continue
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
                r["name"], r["brand"], r["store_name"], r["category"],
                r["description"], r["material"], r["color"], r["gender"],
            ]))
            if not all(w in text for w in words):
                continue
        result.append(r)

    # Həmişə stokda olanlar əvvəl, qalanlar sonda. Qalan sıra "sort" parametrinə görə.
    if sort == "price_asc":
        result.sort(key=lambda r: (r["stock"] <= 0, r["price"]))
    elif sort == "price_desc":
        result.sort(key=lambda r: (r["stock"] <= 0, -r["price"]))
    elif sort == "newest":
        result.sort(key=lambda r: r["stock"] <= 0)
    else:
        # Tövsiyə olunan: ana səhifə üçün seçilmiş məhsullar əvvəl
        result.sort(key=lambda r: (r["stock"] <= 0, 0 if (r["on_home"] or r["store_home_all"]) else 1))
    response.headers["X-Total-Count"] = str(len(result))
    response.headers["Access-Control-Expose-Headers"] = "X-Total-Count"
    return [public_product_dict(r) for r in result[offset:offset + limit]]


@app.get("/api/products/{pid}")
def public_product(pid: int):
    with db() as con:
        rows = approved_rows(con, product_id=pid)
    if not rows:
        raise HTTPException(404, "Məhsul tapılmadı")
    return public_product_dict(rows[0])


# ---------------------------------------------------------------
# İctimai mağazalar
# ---------------------------------------------------------------
@app.get("/api/stores")
def public_stores():
    with db() as con:
        stores = con.execute("SELECT * FROM sellers WHERE status = 'approved'").fetchall()
        counts = {
            r["seller_id"]: r["n"]
            for r in con.execute("SELECT seller_id, COUNT(*) AS n FROM products GROUP BY seller_id")
        }
        covers = {
            r["seller_id"]: r["image_url"]
            for r in con.execute(
                """SELECT seller_id, image_url FROM products
                   WHERE id IN (SELECT MAX(id) FROM products
                                WHERE image_url != '' GROUP BY seller_id)"""
            )
        }

    stores = sorted(stores, key=lambda s: fold(s["store_name"]))
    out = []
    for s in stores:
        d = public_store_dict(s, counts.get(s["id"], 0))
        d["cover_url"] = covers.get(s["id"], "")
        out.append(d)
    return out


@app.get("/api/stores/{sid}")
def public_store(sid: int):
    with db() as con:
        s = con.execute(
            "SELECT * FROM sellers WHERE id = ? AND status = 'approved'", (sid,)
        ).fetchone()
        if not s:
            raise HTTPException(404, "Mağaza tapılmadı")
        rows = approved_rows(con, sid)

    data = public_store_dict(s, len(rows))
    data["products"] = [public_product_dict(r) for r in rows[:200]]
    return data


# ---------------------------------------------------------------
# Admin
# ---------------------------------------------------------------
@app.get("/api/admin/sellers", dependencies=[Depends(require_admin)])
def admin_sellers(status: Optional[str] = None):
    query = """
        SELECT id, store_name, owner_name, category, phone,
               email, city, address, about, whatsapp, instagram,
               tiktok, status, created_at, home_slots, home_all,
               (SELECT COUNT(*) FROM products p WHERE p.seller_id = sellers.id) AS product_count,
               (SELECT COUNT(*) FROM products p
                WHERE p.seller_id = sellers.id AND p.on_home = 1) AS home_used
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


@app.post("/api/admin/sellers/{sid}/status", dependencies=[Depends(require_admin)])
def admin_set_status(sid: int, data: StatusIn):
    if data.status not in ("pending", "approved", "rejected"):
        raise HTTPException(400, "Status yanlışdır")
    with db() as con:
        cur = con.execute("UPDATE sellers SET status = ? WHERE id = ?", (data.status, sid))
        affected = cur.rowcount
        if data.status == "rejected":
            # Rədd edilən satıcının açıq sessiyaları bağlanır
            con.execute("DELETE FROM sessions WHERE seller_id = ?", (sid,))
    if affected == 0:
        raise HTTPException(404, "Satıcı tapılmadı")
    return {"ok": True, "status": data.status}


@app.post("/api/admin/sellers/{sid}/home", dependencies=[Depends(require_admin)])
def admin_seller_home(sid: int, data: SellerHomeIn):
    with db() as con:
        s = con.execute("SELECT id FROM sellers WHERE id = ?", (sid,)).fetchone()
        if not s:
            raise HTTPException(404, "Satıcı tapılmadı")
        if data.slots is not None:
            con.execute("UPDATE sellers SET home_slots = ? WHERE id = ?", (data.slots, sid))
        if data.all is not None:
            con.execute("UPDATE sellers SET home_all = ? WHERE id = ?", (1 if data.all else 0, sid))
        row = con.execute("SELECT home_slots, home_all FROM sellers WHERE id = ?", (sid,)).fetchone()
        used = home_used(con, sid)
    return {
        "ok": True,
        "home_slots": row["home_slots"],
        "home_all": bool(row["home_all"]),
        "home_used": used,
    }


@app.post("/api/admin/products/{pid}/home", dependencies=[Depends(require_admin)])
def admin_product_home(pid: int, data: HomeIn):
    with db() as con:
        cur = con.execute("UPDATE products SET on_home = ? WHERE id = ?", (1 if data.on_home else 0, pid))
        affected = cur.rowcount
    if affected == 0:
        raise HTTPException(404, "Məhsul tapılmadı")
    return {"ok": True, "on_home": data.on_home}


@app.get("/api/admin/products", dependencies=[Depends(require_admin)])
def admin_products():
    with db() as con:
        rows = con.execute(
            """SELECT p.*, s.store_name, s.status AS store_status,
                      s.home_all AS store_home_all
               FROM products p JOIN sellers s ON s.id = p.seller_id
               ORDER BY p.id DESC"""
        ).fetchall()
    result = []
    for r in rows:
        item = product_dict(r)
        item["seller_id"] = r["seller_id"]
        item["created_at"] = r["created_at"]
        item["store_status"] = r["store_status"]
        item["store_home_all"] = bool(r["store_home_all"])
        result.append(item)
    return result


@app.delete("/api/admin/products/{pid}", dependencies=[Depends(require_admin)])
def admin_delete_product(pid: int):
    with db() as con:
        old = con.execute(
            "SELECT seller_id, image_url, images FROM products WHERE id = ?", (pid,)
        ).fetchone()
        if not old:
            raise HTTPException(404, "Məhsul tapılmadı")
        con.execute("DELETE FROM products WHERE id = ?", (pid,))
        for u in row_image_urls(old):
            drop_image(con, old["seller_id"], u)
    return {"ok": True}


# ---------------------------------------------------------------
# Səhifələr və statik fayllar
# ---------------------------------------------------------------
def page(name: str):
    file_path = BASE_DIR / name
    if not file_path.is_file():
        raise HTTPException(404, "Səhifə tapılmadı")
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


# Şəkil, CSS və s. üçün: layihə qovluğunda "static" qovluğu yaradın (məs. static/hero.jpg -> /static/hero.jpg)
if (BASE_DIR / "static").is_dir():
    app.mount("/static", StaticFiles(directory=str(BASE_DIR / "static")), name="static")
