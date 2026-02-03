```md
# نصب و اجرای خودکار Paqet روی Ubuntu 22 — توسط LR4

این ریپو یک اسکریپت یک‌تکه می‌دهد که:

- paqet را داخل `/root` دانلود و اکسترکت می‌کند
- فایل‌های کامل و اصلی example را دقیقاً کپی می‌کند:
  - `example/server.yaml.example` → `/root/server.yaml`
  - `example/client.yaml.example` → `/root/client.yaml`
- فقط همان قسمت‌هایی که لازم است را تغییر می‌دهد (اسم کارت شبکه، MAC گیت‌وی، IP ها، پورت‌ها، سکرت، کامنت کردن IPv6، خاموش کردن socks5 و روشن کردن forward)
- paqet را داخل **screen** اجرا می‌کند
- یک **کران‌جاب** اضافه می‌کند که هر ۱ دقیقه چک کند اگر paqet قطع شده (حتی “Killed”) دوباره اجرا کند

---

## شروع سریع

### 1) فایل install.sh را داخل /root بگذارید

### 2) اجرا
```bash
cd /root
chmod +x install.sh
sudo ./install.sh
اسکریپت خیلی ساده چند تا سوال می‌پرسد:

سرور خارج (Server) یا ایران (Client)

پورت تانل / پورت سرویس / سکرت

اسم screen

لاگ‌ها
لاگ نصب:

/root/paqet-install.log

لاگ اجرای paqet:

/root/paqet-runtime.log

لاگ واچ‌داگ:

/root/paqet-watchdog.log

نمایش زنده:

tail -f /root/paqet-runtime.log
tail -f /root/paqet-watchdog.log
کار با screen
لیست:

screen -ls
وصل شدن:

screen -r LR4-paqet
خارج شدن بدون قطع برنامه:

Ctrl + A سپس D

واچ‌داگ (Restart خودکار)
اسکریپت یک کران‌جاب می‌سازد که هر ۱ دقیقه چک کند.
برای دیدنش:

crontab -l
نکته مهم
اگر زیاد “Killed” می‌بینید، معمولاً یعنی RAM کم است (OOM).
راه‌حل:

سرور قوی‌تر

کاهش سرویس‌های اضافی

اضافه کردن swap (اختیاری)
