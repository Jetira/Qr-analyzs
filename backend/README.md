# QR Security Service Backend

Production-ready FastAPI backend for analyzing QR codes in EV charging stations to detect phishing attacks, malicious redirects, and fake QR sticker replacements.

## 🎯 Purpose

This service protects EV charging station users from "QR Etiketi Değişimiyle Sahte Yönlendirme" (QR Sticker Replacement Phishing) attacks by analyzing QR code contents **before** they are opened by mobile apps.

### Attack Scenario

Attackers physically replace official QR stickers on charging stations with fake ones that redirect users to:
- Phishing web pages (credential theft)
- Malicious APK downloads (malware)
- Typosquatted domains (fake payment pages)

### Solution

The backend analyzes every scanned QR code and returns a security verdict:
- **Safe**: Open URL normally
- **Suspicious**: Show warning to user
- **Malicious**: Block completely

## 🔒 Security Rules

The service implements five security checks:

1. **HTTPS Enforcement** (+60 risk points)
   - Rejects HTTP connections to prevent MITM attacks

2. **Domain Allowlist** (+40 risk points)
   - Validates against official company domains
   - Checks database reputation table

3. **Typosquatting Detection** (+30 risk points)
   - Uses Levenshtein distance algorithm
   - Detects similar-looking domains (e.g., `officia1-domain.com`)

4. **Malicious File Extensions** (+80 risk points)
   - Blocks `.apk`, `.exe`, `.zip`, etc.
   - Prevents malware installation

5. **Dynamic Redirect Detection** (+20 risk points)
   - Flags URL parameters like `?redirect=`
   - Prevents open redirect exploits

**Scoring**: Risk points accumulate to determine verdict:
- `0-39`: Safe
- `40-79`: Suspicious
- `80-100`: Malicious

## 🏗️ Architecture

```
backend/
├── app/
│   ├── main.py              # FastAPI application
│   ├── config.py            # Settings management
│   ├── database.py          # Async SQLAlchemy
│   ├── models.py            # ORM models
│   ├── schemas.py           # Pydantic models
│   ├── logging_utils.py     # Structured logging
│   ├── routers/
│   │   └── qr.py           # API endpoints
│   ├── services/
│   │   └── qr_analyzer.py  # Security analysis engine
│   └── security/
│       └── typosquatting.py # Domain similarity detection
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
└── .env.example
```

## 🚀 Quick Start

### Prerequisites

- Docker & Docker Compose
- (Optional) Python 3.11+ for local development

### 1. Clone and Configure

```bash
cd backend
cp .env.example .env
```

Edit `.env` and configure:
- `DATABASE_URL`: Database connection string
- `OFFICIAL_DOMAINS`: Your company's official domains (comma-separated)

### 2. Start Services

```bash
docker-compose up -d
```

This starts:
- PostgreSQL database on port 5432
- FastAPI backend on port 8000

### 3. Verify Health

```bash
curl http://localhost:8000/health
```

Expected response:
```json
{
  "status": "ok",
  "app": "QR Security Service",
  "version": "1.0.0"
}
```

### 4. View API Documentation

Open your browser to:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## 📡 API Endpoints

### POST `/analyze-qr`

Analyze a QR code for security risks.

**Request:**
```json
{
  "qr_data": "https://example.com/charge",
  "station_id": "CP-001",
  "app_version": "1.0.0",
  "platform": "android"
}
```

**Response:**
```json
{
  "verdict": "safe",
  "score": 0,
  "reasons": ["Güvenli görünüyor: HTTPS kullanılıyor ve resmi domain listesinde"],
  "normalized_url": "https://example.com/charge",
  "host": "example.com"
}
```

### GET `/stations/{station_code}/scans`

Retrieve scan history for a charging station.

**Parameters:**
- `station_code`: Station identifier (e.g., "CP-001")
- `limit`: Max results (default 50, max 200)
- `offset`: Pagination offset (default 0)

### POST `/domains`

Add or update domain reputation.

**Request:**
```json
{
  "host": "suspicious-domain.com",
  "is_official": false,
  "is_denied": true,
  "note": "Reported phishing site"
}
```

### GET `/domains`

List all domain reputation entries.

## 🧪 Testing

### Test Safe URL

```bash
curl -X POST http://localhost:8000/analyze-qr \
  -H "Content-Type: application/json" \
  -d '{
    "qr_data": "https://official-domain.com/charge/station123",
    "station_id": "CP-001"
  }'
```

Expected: `verdict: "safe"`

### Test Malicious APK

```bash
curl -X POST http://localhost:8000/analyze-qr \
  -H "Content-Type: application/json" \
  -d '{
    "qr_data": "http://fake-domain.com/charge.apk",
    "station_id": "CP-001"
  }'
```

Expected: `verdict: "malicious"`, reasons include:
- "HTTPS değil"
- "Potansiyel zararlı dosya indirme (APK)"

### Test Typosquatting

```bash
curl -X POST http://localhost:8000/analyze-qr \
  -H "Content-Type: application/json" \
  -d '{
    "qr_data": "https://officia1-domain.com/charge",
    "station_id": "CP-001"
  }'
```

Expected: `verdict: "suspicious"`, detects Levenshtein distance

## 🗄️ Database Schema

### Station
- Represents EV charging stations
- Fields: `id`, `station_code`, `location`, `is_active`

### QRScan
- Audit log of all QR code analyses
- Fields: `id`, `station_id`, `raw_qr_data`, `parsed_url`, `host`, `verdict`, `score`, `reasons`, `app_version`, `platform`, `created_at`

### DomainReputation
- Allowlist/denylist for domain validation
- Fields: `id`, `host`, `is_official`, `is_denied`, `note`

### Query Database

```bash
docker-compose exec db psql -U postgres -d qr_security

# List all scans
SELECT * FROM qr_scans ORDER BY created_at DESC LIMIT 10;

# Count verdicts
SELECT verdict, COUNT(*) FROM qr_scans GROUP BY verdict;
```

## 🔧 Development

### Local Development (without Docker)

1. Install PostgreSQL locally
2. Create virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # Windows: venv\Scripts\activate
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure `.env` with local database URL
5. Run server:
   ```bash
   uvicorn app.main:app --reload
   ```

### Hot Reload with Docker

Uncomment the volume mount in `docker-compose.yml`:
```yaml
volumes:
  - ./app:/app/app
```

Then restart:
```bash
docker-compose restart api
```

## 📊 Production Deployment

### Security Checklist

- [ ] Change default PostgreSQL password
- [ ] Configure actual `OFFICIAL_DOMAINS`
- [ ] Set specific CORS origins (remove `*`)
- [ ] Enable HTTPS/TLS termination (use reverse proxy)
- [ ] Set up log aggregation (ELK, Splunk, CloudWatch)
- [ ] Implement authentication for `/domains` endpoint
- [ ] Use managed database (AWS RDS, Google Cloud SQL)
- [ ] Enable database backups
- [ ] Set up monitoring and alerts
- [ ] Review and rotate secrets regularly

### Environment Variables

See `.env.example` for detailed configuration options.

Critical settings for production:
- `DATABASE_URL`: Use strong password and SSL
- `OFFICIAL_DOMAINS`: Carefully curate this list
- `CORS_ORIGINS`: Whitelist specific mobile app origins
- `LOG_LEVEL`: Set to `INFO` or `WARNING`

### Scaling

For high traffic:
- Use multiple API instances behind a load balancer
- Enable database connection pooling
- Consider Redis for caching domain reputation
- Implement rate limiting (e.g., with nginx or API Gateway)

## 📝 Logging

The service outputs JSON-formatted logs for SIEM integration:

```json
{
  "event_type": "qr_scan",
  "timestamp": "2025-11-22T18:00:00",
  "station_id": "CP-001",
  "verdict": "malicious",
  "score": 140,
  "url": "http://fake.com/app.apk",
  "host": "fake.com",
  "platform": "android",
  "app_version": "1.0.0"
}
```

View logs:
```bash
docker-compose logs -f api
```

## 🛠️ Future Enhancements

### JWT Dynamic QR Validation (Placeholder Implemented)

Concept:
- Official QR codes embed JWT tokens
- Token contains: `station_id`, `exp`, `nonce`
- Backend validates signature and expiration
- Prevents physical QR replacement attacks

Implementation:
- Add PyJWT to requirements
- Implement `verify_dynamic_qr_token()` in `qr_analyzer.py`
- Use Redis for nonce replay protection

### Real-Time URL Reputation

- Integrate with external reputation APIs (VirusTotal, Google Safe Browsing)
- Perform HTTP HEAD requests to check redirects
- Analyze page content for phishing indicators

## 📄 License

[Your License Here]

## 👥 Support

For issues or questions:
- Create a GitHub issue
- Contact security team: [Your Contact]

## 🎓 References

- [OWASP QR Code Security](https://owasp.org/www-community/attacks/Qrljacking)
- [Typosquatting Detection](https://en.wikipedia.org/wiki/Typosquatting)
- [FastAPI Documentation](https://fastapi.tiangolo.com/)
- [SQLAlchemy Async](https://docs.sqlalchemy.org/en/20/orm/extensions/asyncio.html)
