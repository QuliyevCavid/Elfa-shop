# ELFA Marketplace — Satıcı təsdiq sistemi

Bu paket ELFA-nın mövcud müştəri səhifəsini saxlayır və əlavə edir:
- Satıcı qeydiyyatı (`seller-register.html`)
- Satıcı girişi və məhsul idarəetməsi (`seller.html`)
- Administrator girişi və satıcı təsdiqi (`admin.html`)
- FastAPI backend + SQLite verilənlər bazası
- Yalnız təsdiqlənmiş satıcıların məhsullarını qaytaran public API (`/api/products`)

## Windows-da işə salmaq

1. Python 3.11 və ya daha yeni versiya quraşdırılsın.
2. Bu qovluğu aç, ünvan sətrinə `cmd` yazıb Enter bas.
3. Virtual mühit yarat və aktivləşdir:

```bat
py -m venv .venv
.venv\Scripts\activate
```

4. Paketləri quraşdır:

```bat
pip install -r requirements.txt
```

5. Administrator hesabı üçün mühit dəyişənlərini təyin et (öz e-poçtunu və güclü şifrəni yaz):

```bat
set ADMIN_EMAIL=admin@senindomenin.az
set ADMIN_PASSWORD=BurayaGücluVeUnikalSifreYaz
```

6. Serveri başlad:

```bat
uvicorn backend.main:app --reload
```

7. Brauzerdə aç:
- Müştəri saytı: `http://127.0.0.1:8000/`
- Satıcı qeydiyyatı: `http://127.0.0.1:8000/seller-register.html`
- Satıcı paneli: `http://127.0.0.1:8000/seller.html`
- Administrator paneli: `http://127.0.0.1:8000/admin.html`
- API yoxlaması: `http://127.0.0.1:8000/api/health`

## İş axını

1. Satıcı qeydiyyatdan keçir və statusu `pending` olur.
2. Satıcı panelinə daxil olanda “Təsdiq gözləyir” mesajını görür.
3. Administrator `/admin.html` səhifəsinə daxil olub satıcını təsdiqləyir və ya rədd edir.
4. Təsdiqlənmiş satıcı məhsul əlavə edə bilər.
5. Müştəri ana səhifəsindəki “Satıcı mağazalarından” bölməsində təsdiqlənmiş satıcıların məhsulları görünür.

## Vacib qeydlər

- Administrator hesabı yalnız `ADMIN_EMAIL` və `ADMIN_PASSWORD` dəyişənləri server ilk dəfə başladılan zaman qurulur. Bu dəyərləri başqaları ilə paylaşma.
- Yerli test üçün `COOKIE_SECURE=0` qalır. HTTPS ilə yayımlayanda `COOKIE_SECURE=1` təyin et.
- Bu başlanğıc versiyadır. İctimai yayımdan əvvəl HTTPS, server səviyyəsində rate limiting, ehtiyat nüsxə, e-poçt təsdiqi, şifrə sıfırlama, moderasiya qaydaları və təhlükəsizlik auditi əlavə edilməlidir.
- Mövcud ana səhifədəki nümunə məhsullar demo məzmunudur. Yeni satıcı məhsulları verilənlər bazasından ayrıca göstərilir.
- Sifariş, çatdırılma və ödənişin satıcılar arasında bölüşdürülməsi bu mərhələyə daxil deyil; növbəti mərhələdə ayrıca qurulmalıdır.
