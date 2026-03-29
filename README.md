# A-tool

> نسخة دفاعية تعليمية لبناء **Intrusion Detection System (IDS)** بسيط.

هذا المشروع يقدم نموذج أولي يكتشف 3 أنواع هجمات شائعة:

- **DDoS** (فيض طلبات من نفس الـ IP)
- **Brute Force** (محاولات تسجيل دخول فاشلة متكررة)
- **Port Scanning** (تجربة عدد كبير من المنافذ بسرعة)

ويقدم:

- 🚨 **تنبيه مباشر** في الطرفية
- 🔒 **حظر IP تلقائي** في ملف `blocked_ips.txt`
- 📊 **Dashboard** في `dashboard.html` + `dashboard.json`

## التشغيل

```bash
python ids_system.py --events-csv sample_events.csv --brute-threshold 8 --scan-threshold 12 --ddos-threshold 50
```

بعد التشغيل ستجد:

- `dashboard.html`
- `dashboard.json`
- `blocked_ips.txt`

## صيغة ملف الأحداث CSV

لازم يحتوي الأعمدة التالية:

- `timestamp` (Unix timestamp)
- `source_ip`
- `event_type` (مثل: `request`, `login`)
- `status` (مثل: `ok`, `failed`)
- `dest_port`

## ملاحظات مهمة

- هذا مشروع **دفاعي/تعليمي** وليس نظام إنتاج جاهز.
- يفضّل دمجه مع سجلات حقيقية (Firewall, Web Server, Auth logs) لمخرجات أدق.
- يمكنك تعديل عتبات الاكتشاف باستخدام الخيارات:
  - `--ddos-threshold`
  - `--brute-threshold`
  - `--scan-threshold`
  - `--window-seconds`
