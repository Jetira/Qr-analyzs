# 🛡️ QR Security Analyzer (ChargeSentinel)

**Yapay Zeka Destekli QR Kod Güvenlik Analiz Platformu**

Bu proje, Elektrikli Araç (EV) şarj istasyonlarında ve genel kullanımda karşılaşılan kötü amaçlı QR kod saldırılarını (Quishing) tespit etmek ve engellemek için geliştirilmiş gelişmiş bir siber güvenlik çözümüdür.

![Project Banner](https://img.shields.io/badge/Security-A%2B-green) ![Python](https://img.shields.io/badge/Python-3.10%2B-blue) ![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-teal) ![License](https://img.shields.io/badge/License-MIT-orange)

## 🚀 Proje Özellikleri

### 1. Gelişmiş Risk Analiz Motoru
Sistem, taranan her URL'i 7 farklı güvenlik katmanından geçirir:
- **HTTPS Zorunluluğu:** Şifrelenmemiş bağlantıları (HTTP) tespit eder.
- **Domain İtibar Kontrolü:** Resmi ve güvenilir (Google, Apple vb.) domainleri tanır.
- **Typosquatting Tespiti:** Resmi domainlere benzeyen sahte domainleri (örn: `g00gle.com`) yakalar.
- **Malware Analizi:** `.apk`, `.exe` gibi zararlı dosya indirme girişimlerini engeller.
- **Phishing Tespiti:** URL içindeki şüpheli anahtar kelimeleri (`login`, `password`, `bank`) analiz eder.
- **Redirect Analizi:** Kullanıcıyı fark ettirmeden başka siteye yönlendiren parametreleri inceler.

### 2. Akıllı Sınıflandırma Sistemi
Yanlış alarmları (False Positive) önlemek için 3 katmanlı mimari kullanır:
- ✅ **Güvenli (Safe):** Resmi kurumlar ve bilinen güvenilir servisler (Google, Apple, GitHub vb.).
- ⚠️ **Şüpheli (Suspicious):** Bilinmeyen domainler veya hafif risk faktörleri.
- 🚫 **Tehlikeli (Malicious):** Açık tehdit içeren, kara listedeki veya saldırı imzası taşıyan URL'ler.

### 3. Modern Web Arayüzü
- Kullanıcı dostu, responsive tasarım.
- Anlık analiz sonuçları ve görsel risk göstergeleri.
- QR kod görseli yükleyerek analiz yapabilme özelliği.

## 🛠️ Kurulum ve Çalıştırma

Projeyi yerel ortamınızda çalıştırmak için:

```bash
# 1. Repoyu klonlayın
git clone https://github.com/kullaniciadiniz/qr-security-analyzer.git
cd qr-security-analyzer

# 2. Sanal ortam oluşturun
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\activate

# 3. Bağımlılıkları yükleyin
pip install -r requirements.txt

# 4. Uygulamayı başlatın
python -m uvicorn app.main:app --reload
```

Tarayıcınızda **http://localhost:8000** adresine gidin.

## 🏗️ Teknoloji Yığını

- **Backend:** Python, FastAPI, SQLAlchemy, Pydantic
- **Veritabanı:** SQLite (Geliştirme), PostgreSQL (Prodüksiyon uyumlu)
- **Analiz:** BeautifulSoup4 (HTML Parsing), Pyzbar (QR Decoding)
- **Frontend:** HTML5, CSS3 (Modern UI), JavaScript (Vanilla)

## 📊 API Dokümantasyonu

Swagger UI üzerinden API endpoint'lerini test edebilirsiniz:
`http://localhost:8000/docs`

### Örnek Analiz İsteği
```json
POST /api/v1/analyze/url
{
  "url": "http://hizli-sarj.com/login.php?token=123",
  "client_app": "web-dashboard"
}
```

## 👥 Ekip
- **Ad Soyad:** [Adınız Soyadınız]
- **Öğrenci No:** [Numaranız]
- **Ders:** [Ders Adı]

---
&copy; 2025 QR Security Analyzer. Tüm hakları saklıdır.
