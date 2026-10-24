# 🎤 AXON — Pitch Deck

عرض المستثمرين · 15 شريحة · عربي (RTL) · تصميم داكن "غرفة تحكّم".

## الملفات
| الملف | الوصف |
|---|---|
| `axon-deck.html` | العرض التفاعلي — افتحه بالمتصفح |
| `AXON-Deck.pdf` | نسخة PDF جاهزة للإرسال (15 صفحة) |

## التحكّم
| المفتاح | الوظيفة |
|---|---|
| `→` `←` `↑` `↓` `Space` | التنقل بين الشرائح |
| `F` | ملء الشاشة |
| `P` | حفظ كـPDF |
| `Home` / `End` | أول / آخر شريحة |
| نقر · عجلة · سحب | تنقّل سريع |
| `#5` بالرابط | القفز لشريحة محددة |

## إعادة توليد الـPDF
```bash
cd pitch
python3 -m http.server 12000 &
chromium --headless --disable-gpu --no-sandbox --no-pdf-header-footer \
  --print-to-pdf=AXON-Deck.pdf --virtual-time-budget=12000 \
  http://localhost:12000/axon-deck.html
```

## ملاحظات المتحدث
في [`../AXON-PITCH.md`](../AXON-PITCH.md) — نص لكل شريحة + أسئلة متوقّعة + بريد المستثمرين.
