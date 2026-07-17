# BugBîner AI — Gen AI-Powered Vulnerability Scanner v1

<p align="center">
  <b>ماسح ثغرات أمنية مدعوم بالذكاء الاصطناعي التوليدي</b><br>
  <sub>Built by Joudi Janble</sub>
</p>

---

## نبذة عن البرنامج

**BugBîner AI** هو ماسح ثغرات أمنية عصري يدمج بين تقنيات الفحص  والذكاء الاصطناعي التوليدي المحلي. يكتشف البرنامج أكثر من **60 نوعاً** من الثغرات الأمنية تلقائياً ويقدم تحليل ذكي لكل ثغرة مع تقييم مدى استغلالها.
ومازال قيد تطوير 

### روابط مفيدة
- فيديو شرح: https://www.youtube.com/watch?v=exnomF4Ccn4
- فيسبوك: https://www.facebook.com/joudijanble

### المميزات الرئيسية

| الميزة | الوصف |
|---|---|
| **زحف تلقائي (Burp-style Spider)** | زاحف Node.js + Puppeteer يكتشف جميع صفحات الموقع تلقائياً |
| **60+ كاشف ثغرات** | XSS, SQLi, SSRF, SSTI, IDOR, XXE, LFI, CSRF, RCE, Open Redirect, Path Traversal والمزيد |
| **تحليل ذكي بالـ AI** | كل ثغرة تُحلل بالذكاء الاصطناعي لتحديد ما إذا كانت حقيقية أو إيجابي كاذب |
| **استغلال تجريبي (PoC)** | توليد تلقائي لـ Proof of Concept لكل ثغرة مكتشفة |
| **اختبار خارج النطاق (OAST)** | اختبار SSRF العمياء والثغرات العمياء عبر interactsh |
| **DOM XSS Detection** | فحص XSS في تطبيques Single Page عبر Playwright + Chromium |
| **تقارير HTML احترافية** | تقارير مفصلة تشبه Burp Suite مع تصنيف حسب الخطورة |
| **استئناف الفحص (Resume)** | إمكانية إيقاف مؤقت واستئناف الفحص من حيث توقف |
| **واجهة عصرية** | واجهة سوداء بأسلوب Cyberpunk مع لوحة متابعة حية |
| **ذكاء اصطناعي محلي بالكامل** يعمل بدون انترنت مجاني بالكامل

---

## الأنواع المكتشفة من الثغرات

### فئة 1 — فحص نشط (Active Scan)
| الثغرة | الوصف |
|---|---|
| **XSS** | Cross-Site Scripting — Reflected, Stored, DOM-based |
| **SQLi** | SQL Injection — Error-based, Blind, Time-based |
| **SSTI** | Server-Side Template Injection — Jinja2, Twig, Freemarker |
| **SSRF** | Server-Side Request Forgery — مع اختبار Cloud Metadata |
| **XXE** | XML External Entity Injection |
| **LFI / Path Traversal** | Local File Inclusion وتجاوز المسارات |
| **RCE** | Remote Code Execution — Command Injection |
| **CRLF Injection** | تسميم Headers عبر CRLF |
| **Header Injection** | حقن Headers عشوائية |

### فئة 2 — فحص تفاعلي (Pro Active)
| الثغرة | الوصف |
|---|---|
| **IDOR / BOLA** | Insecure Direct Object Reference — فحص بحسابين مختلفين |
| **CSRF** | Cross-Site Request Forgery — على Forms الحالة المعدلة |
| **Open Redirect** | إعادة توجيه مفتوحة مع اختبار evil.com |
| **JWT Attacks** | اختبار توقيعات JSON Web Token |
| **GraphQL** | اختبار GraphQL endpoints |
| **NoSQL Injection** | حقن قواعد بيانات NoSQL |
| **Clickjacking** | اختبار X-Frame-Options |
| **Mass Assignment** | اختبار تعديل الحقول المخفية (BOPLA) |
| **Subdomain Takeover** | اختبار الاستحواذ على النطاقات الفرعية |
| **Secret Exposure** | كشف API Keys, Tokens, Passwords المكشوفة |

### فئة 3 — فحص مخصص (Burp-class Turbo)
| الثغرة | الوصف |
|---|---|
| **HTTP Smuggling** | تهريب HTTP Requests |
| **DNS Rebinding** | إعادة ربط DNS |
| **Race Conditions** | سباق الحالتين |
| **Prototype Pollution** | تلوث النماذج في JavaScript |
| **WebSocket** | اختبار WebSocket endpoints |
| **DOM XSS Static** | تحليل ثابت لـ DOM XSS |
| **Cache Poisoning** | تسميم الكاش |
| **File Upload Bypass** | تجاوز رفع الملفات |

---

## المتطلبات

| المكون | الإصدار |
|---|---|
| **Windows** | 10/11 |
| **Python** | 3.12+ |
| **Node.js** | LTS |

---

## طريقة التشغيل

### الطريقة السريعة (موصى بها)

```bash
# 1. انسخ المستودع
git clone https://github.com/your-username/bugbiner-ai.git
cd bugbiner-ai

# 2. شغّل المُشغّل — يتطلب ويُثبّت كل شيء تلقائياً
start.bat
```

**المُشغّل `start.bat` يقوم بالتالي تلقائياً:**

```
1. يتحقق من Python ويُثبّته إذا لم يكن موجوداً
2. ينشئ بيئة افتراضية (venv) ويُثبّت المكتبات
3. يتحقق من Node.js ويُثبّته + Puppeteer إذا لم يكونا موجودين
4. يضبط إعدادات التشغيل المتوازي
5. يشغّل الخادوم على المنفذ 9090
6. يفتح المتصفح تلقائياً
```

### فتح الواجهة

```
http://localhost:9090
```

---

## كيفية استخدامه

### 1. بدء الفحص
- أدخل رابط الموقع المستهدف في حقل **Target URL**
- اختر أنواع الثغرات المطلوبة من قائمة **Select Vulnerabilities**
- اضغط **Start Scan**

### 2. متابعة النتائج حياً
- **Terminal**: يعرض أحداث الزحف والفحص لحظياً
- **Live Dashboard**: يعرض كل صفحة تم اكتشافها وحالة فحصها
- **Site Map**: خريطة شجرية للموقع مثل Burp Suite
- **AI Panel**: يعرض تحليل الذكاء الاصطناعي للتقنيات المكتشفة

### 3. عرض الثغرات
- **Findings Bar**: شريط علوي يعرض عدد الثغرات حسب الخطورة
- **Vuln Panel**: لوحة مفصلة لكل ثغرة مع البرهان والاستغلال والتوصيات
- **Vuln Details**: AI Verdict + Exploitability + Attack Scenario + Fix

### 4. التقارير
- اضغط **Generate Report** لإنشاء تقرير HTML مفصل
- التقارير تُحفظ في مجلد `reports/`

### 5. إيقاف واستئناف
- **Pause**: إيقاف مؤقت — يُحفظ كل شيء
- **Resume**: استئناف من حيث توقف (يُعاد تحميل الصفحة بشكل شفاف)
- **Stop**: إيقاف نهائي مع حفظ التقدم

---

## ملاحظات تقنية

- **يعمل بالكامل محلياً** — لا يحتاج إنترنت بعد تحميل النموذج
- **بياناتك آمنة** — لا يتم إرسال أي بيانات لأي خادوم خارجي
- **Fingerprinting ذكي** — يكتشف تقنيات الموقع قبل بدء الفحص لتخصيص الكاشفات
- **Adaptive Baseline** — يقارن الاستجابة العادية مع استجابة الحمولة لكل URL
- **Differential Confirmation** — يؤكد الثغرة بمقارنة النتيجة مع التحكم والخط الأساسي
- **False Positive Suppression** — فلترة تلقائية للإيجابيات الكاذبة المعروفة
- **Deduplication** — لا يكرر نفس الثغرة مرتين

---

## الترخيص

هذا المشروع للاستخدام التعليمي والأبحاث الأمنية فقط. استخدامه على مواقع بدون إذن مخالف للقانون.

---

<p align="center">
  <b>BugBiner AI</b> — Vulnerability Scanner Powered by Generative AI<br>
  <sub>Built with FastAPI, Node.js, Puppeteer, Playwright</sub>
</p>
