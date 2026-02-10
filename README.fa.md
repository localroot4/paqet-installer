# نصب و اجرای خودکار Paqet روی لینوکس — توسط LR4

این ریپو یک اسکریپت **تک‌فایل** می‌دهد که:

- Paqet را داخل `/root` دانلود و اکسترکت می‌کند
- فایل‌های کامل و اصلی مثال‌ها را دقیقاً کپی می‌کند:
  - `example/server.yaml.example` → `/root/server.yaml`
  - `example/client.yaml.example` → `/root/client.yaml`
- فقط قسمت‌های لازم را تغییر می‌دهد (کارت شبکه، MAC، IPها، پورت‌ها، سکرت، کامنت IPv6، خاموش‌کردن SOCKS5 و فعال‌کردن forward)
- Paqet را داخل **screen** اجرا می‌کند
- یک **واچ‌داگ** (هر ۱ دقیقه با systemd یا cron) اضافه می‌کند تا در صورت قطع شدن Paqet دوباره اجرا شود

---

## سازگاری

- **سیستم‌عامل:** توزیع‌های لینوکسی با پکیج‌منیجرهای پشتیبانی‌شده (`apt`, `dnf`, `yum`, `apk`, `pacman`, `zypper`).
- **پردازنده:** `amd64`، `arm64`، `armhf` (تشخیص خودکار).

> اگر توزیع شما لیست نشده، وابستگی‌ها را دستی نصب کنید: curl, wget, screen, iproute2, iputils/ping, perl, file, tar, procps/pgrep.

---

## شروع سریع (تعامل‌پذیر)

```bash
cd /root
chmod +x install.sh
sudo ./install.sh
```

اسکریپت می‌پرسد:

- حالت: **سرور خارج** یا **کلاینت ایران**
- پورت‌ها و **سکرت**
- آی‌پی سرور خارج (برای کلاینت)

---

## دستورهای تک‌خطی

### تعامل‌پذیر (همه سوال‌ها را می‌پرسد)

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

### بدون تعامل با ENV (تک‌خطی)

**سرور خارج:**

```bash
MODE=server SECRET='change-me' TUNNEL_PORT=9999 bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

**کلاینت ایران:**

```bash
MODE=client SECRET='change-me' TUNNEL_PORT=9999 SERVICE_PORT=8080 OUTSIDE_IP='1.2.3.4' bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

---

## شروع سریع (بدون تعامل / Pipe)

اگر با `curl | bash` اجرا می‌کنید باید متغیرها را بدهید:

```bash
MODE=server SECRET='change-me' TUNNEL_PORT=9999 \
  bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

**نمونه کلاینت:**

```bash
MODE=client SECRET='change-me' TUNNEL_PORT=9999 SERVICE_PORT=8080 OUTSIDE_IP='1.2.3.4' \
  bash <(curl -fsSL https://raw.githubusercontent.com/localroot4/paqet-installer/main/install.sh)
```

---

## متغیرهای محیطی

- `MODE=server|client`
- `SECRET='...'`
- `TUNNEL_PORT=9999`
- `SERVICE_PORT=8080` (کلاینت)
- `OUTSIDE_IP='x.x.x.x'` (کلاینت)
- `PUBLIC_IP='x.x.x.x'` (سرور؛ اختیاری)
- `LOCAL_IP='x.x.x.x'` (کلاینت؛ اختیاری)
- `SCREEN_NAME=LR4-paqet`
- `SCREEN_NAME` برای تعیین نام سشن screen است (در حالت تعاملی پرسیده می‌شود).
- `AUTO_START=1|0`
- `AUTO_ATTACH=1|0` (اتصال خودکار به screen در انتها وقتی TTY موجود است)
- `SKIP_PKG_INSTALL=1|0` (اگر ۱ باشد نصب وابستگی‌ها انجام نمی‌شود)
- `WATCHDOG=1|0`
- `WATCHDOG_METHOD=auto|cron|systemd`

---

## لاگ‌ها

- لاگ نصب: `/root/paqet-install.log`
- لاگ اجرای Paqet: `/root/paqet-runtime.log`
- لاگ واچ‌داگ: `/root/paqet-watchdog.log`

نمایش زنده:

```bash
tail -f /root/paqet-runtime.log
```

---

## کار با Screen

- لیست: `screen -ls`
- وصل شدن: `screen -r LR4-paqet`
- خروج بدون قطع برنامه: `Ctrl + A` سپس `D`

---

## رفع خطا

- **نمایش “Killed” در لاگ:** معمولاً کمبود RAM (OOM).
  - سرور قوی‌تر
  - توقف سرویس‌های اضافی
  - اضافه کردن swap (اختیاری)

- **تشخیص‌ندادن MAC گیت‌وی:** تنظیمات شبکه را بررسی کنید یا خروجی `ip r` را ببینید.
