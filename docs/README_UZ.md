# Linux xavfsizlik auditori — o‘zbekcha qo‘llanma

[Asosiy README](../README.md) · [English](README_EN.md) · [Русский](README_RU.md)

Linux Security Auditor kompyuterdagi cheklangan xavfsizlik sozlamalarini **faqat o‘qib** tekshiradi. Natijada dalil bilan tasdiqlangan holatlar, tekshirib bo‘lmagan holatlar va tegishli bo‘lmagan tekshiruvlar alohida ko‘rsatiladi. Dastlabki qoida sinovlari Ubuntu 22.04/24.04 va Debian 12 uchun mo‘ljallangan.

## Ishga tushirish

```bash
python3.12 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python main.py
```

**Kompyuterni tekshirish** tugmasini bosing. Jild ruxsatlarini ko‘rish uchun uni o‘zingiz tanlang; dastur fayl mazmunini o‘qimaydi, symlinklarni chetlab o‘tadi va tekshiruv hajmini cheklaydi. **Topilmalar** bo‘limida dalil, manba, ta’sir va qo‘lda bajariladigan tavsiya ko‘rinadi. **Bo‘limlar** tegishli topilmalarni filtrlaydi. **Hisobotlar** HTML, PDF va JSON shaklida mahalliy saqlanadi. **Sozlamalar** maxfiylik va usulni tushuntiradi. Til yuqoridan tanlanadi va qayta ochilganda saqlanadi.

## Holatlar

`PASS` — aynan shu qoida mavjud dalil asosida o‘tgan; bu umumiy xavfsizlik kafolati emas. `WARN` va `FAIL` inson ko‘rib chiqishini talab qiladi. `UNKNOWN` — dalil yetarli emas. `NOT_APPLICABLE` — tekshiruv tegishli emas, masalan SSH server yo‘q. Dastur tavsiya qilingan tizim o‘zgarishlarini bajarmaydi. [Qoidalar](RULE_CATALOG.md) · [Usul](METHODOLOGY.md) · [Xavfsizlik](SECURITY.md).

## Haqiqiy tasvirlar

[Jonli o‘zbekcha oyna](screenshots/dashboard-uz.png) · [Jonli topilmalar](screenshots/findings-live.png) · [Jonli hisobot oynasi](screenshots/report-preview-live.png). Tasvirlar Ubuntu 24.04 dagi real PySide6 dasturidan olingan. Jonli hisobotlar maxfiylik uchun repoga joylanmaydi.

## Cheklovlar

Bu kirib borish testi, CIS sertifikati yoki to‘liq himoya isboti emas. Oddiy foydalanuvchi amaldagi firewall qoidalarini ko‘ra olmasligi mumkin. APT keshi eskirishi mumkin. Sinov uchun `QT_QPA_PLATFORM=offscreen .venv/bin/python -m pytest -q` va `.venv/bin/python -m ruff check .` buyruqlarini bajaring. [Sinovlar](TESTING.md) · [Platformalar](PLATFORMS.md).
