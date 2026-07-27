# 🚀 GhostRPC

این برنامه یک تونل ارتباطی سریع با واسطه‌ Cloudflare CDN و بر بستر HTTP/2 (همراه با فرمت‌دهی gRPC) می‌باشد که برای عبور از سیستم‌های فیلترینگ طراحی شده است.

---

## ✨ قابلیت‌های کلیدی

### ۱. معماری انتقال سریع و پایدار
ترافیک این تونل از نگاه سیستم‌های مانیتورینگ کاملاً شبیه به وبگردی عادی یا یک درخواست استاندارد gRPC از Cloudflare است. هیچ نوع رمزنگاری اضافه و تکراری وجود ندارد.

### ۲. پشتیبانی بومی از TCP و UDP
تانل GhostRPC علاوه بر ترافیک TCP، از استریم‌های UDP خام (مثل تماس‌های صوتی و بازی‌ها) بر بستر پروتکل پایدار HTTP/2 کاملاً همزمان پشتیبانی می‌کند.

### ۳. دفاع هوشمند (Active Probing Defense)
در صورت اسکن شدن سرور شما توسط ربات‌های فیلترینگ یا درخواست در مسیری به غیر از مسیر مخفی تونل، سرور می‌تواند محتوای یک سایت مجاز (Proxy) را برای استتار نمایش دهد.

### ۴. مدیریت گواهینامه اتوماتیک (Zero-Config ACME)
کلاینت و سرور هر دو قابلیت دریافت و تمدید خودکار گواهینامه‌ی Let's Encrypt (از طریق DNS-01 Cloudflare) را دارند.

### ۵. مسیریابی پیشرفته (SNI Multiplexing & Web Server)
دو لایه مسیریابی قدرتمند هم در کلاینت و هم در سرور وجود دارد:
- `sni_proxy` / `port_mappings`: خواندن SNI از پکت خام `ClientHello` بدون رمزگشایی و فوروارد به مقصد (Zero-Copy).
- `web_server`: قابلیت وب‌سرور داخلی (مشابه Caddy) که از ۳ حالت مختلف (`reverse_proxy`, `static`, `fastcgi`) برای لایه ۷ پشتیبانی می‌کند.

### ۶. بارگذاری مجدد بدون قطعی (Zero-Downtime Hot-Reload)
ذخیره تغییرات فایل‌های کانفیگ بلافاصله و بدون هیچ قطعی (در صدم‌ثانیه) روی کانکشن‌های جدید اعمال می‌شود در حالی که ارتباط کاربران قبلی تا آخرین لحظه باز می‌ماند.

### ۷. کلاینت هوشمند (IP Scanner & Pool)
کلاینت با اسکن مداوم لیست آی‌پی‌های تمیز کلودفلر، همواره به بهترین و سریع‌ترین آی‌پی‌ها متصل می‌شود و از قابلیت استخر توزیع‌شده برای استفاده همزمان از تمام ریموت‌ها با قابلیت به اشتراک‌گذاری SNI بر اساس اولویت‌بندی بهره می‌برد.

---

## 🛠 راهنمای نصب و اجرا

```bash
# کامپایل برنامه
./build.sh

# اجرای سرور
./GhostRPC server.toml

# اجرای کلاینت
./GhostRPC client.toml
```

---

## ⚙️ نمونه تنظیمات

### کانفیگ سرور (`server.toml`)
```toml
[server]
bind_addr = "0.0.0.0:443"
secret = "my_super_secret_password"
hidden_path = "/api/v4/telemetry"
tls_cert = "fullchain.pem"
tls_key = "privkey.pem"
camouflage_target = "https://www.ubuntu.com"
cloudflare_api_token = "YOUR_CLOUDFLARE_API_TOKEN"
acme_domains = ["domain.com", "*.domain.com"]
log_level = "info"

tunnel_sni = [
    "tunnel1.domain.com",
    "tunnel2.domain.com"
]

# روتینگ مستقیم بدون بازگشایی رمزنگاری
sni_proxy = [
    "raw.domain.com:443=127.0.0.2:443"
]

# قابلیت وب‌سرور داخلی (مشابه Caddy) برای پاسخگویی به درخواست‌های لایه ۷
[[server.web_server]]
domain = "panel.domain.com:443"
[[server.web_server.routes]]
path = "*"
type = "reverse_proxy"
target = "127.0.0.1:8080"
```

### کانفیگ کلاینت (`client.toml`)
```toml
[client]
hidden_path = "/api/v4/telemetry"
secret = "my_super_secret_password"
pool_size_per_node = 16
accept_udp = "yes"
log_level = "info"

# در صورت ست شدن توکن، کلاینت هم مانند سرور برای خودش گواهینامه می‌گیرد
# cloudflare_api_token = "YOUR_TOKEN"
# acme_domains = ["local.domain.com"]
# tls_cert = "fullchain.pem"
# tls_key = "privkey.pem"

# وب‌سرور لایه ۷ در کلاینت (ارتباطی به تونل ندارد)
[[client.web_server]]
domain = "local.domain.com:443"
[[client.web_server.routes]]
path = "*"
type = "reverse_proxy"
target = "127.0.0.1:8080"

# آی‌پی اسکنر
clean_ip_file = "clean_ips.txt"
source_ips_file = "source_ips.txt"
check_interval_minutes = 60
max_ping_ms = 150

# ریموت لوکیشن NL
[[client.remotes]]
location = "NL"
share_sni = 0  # عدم اشتراک‌گذاری SNI
sni = [
    "sni1.example.com:443",
]
port_mappings = [
    "sni.nl.example.com:443=127.0.0.1:443",
    "1373=1373"
]

# ریموت لوکیشن DE
[[client.remotes]]
location = "DE"
share_sni = 1  # اولویت 1 برای اشتراک‌گذاری (قابلیت Fallback)
sni = [
    "sni3.example.com:443"
]
port_mappings = [
    "sni.de.example.com:443=127.0.0.1:443"
]
```
