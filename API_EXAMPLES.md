# ChargeSentinel QR Security Service - Example API Requests

This document shows how to test the new v1 API endpoints.

## Prerequisites

```bash
# Install dependencies
pip install -r requirements.txt

# Start the server
python -m uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

## API Endpoints

### 1. URL Analysis - `POST /api/v1/analyze/url`

Analyze a URL for security risks.

#### Example 1: Trusted Domain (Google)

```bash
curl -X POST "http://localhost:8000/api/v1/analyze/url" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "https://www.google.com"
  }'
```

**Expected Response:**
- `category`: "trusted_third_party"
- `risk_score`: 10 (low)
- `risk_level`: "low"
- `reasons`: ["Domain is in trusted third-party list (Google)"]

#### Example 2: Suspicious URL

```bash
curl -X POST "http://localhost:8000/api/v1/analyze/url" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://sketchy-site.com/login.php?reset=token&password=verify"
  }'
```

**Expected Response:**
- `category`: "unknown_or_untrusted"
- `risk_score`: 60+ (medium/high)
- `risk_level`: "medium" or "high"
- `reasons`: Multiple warnings about HTTP, suspicious keywords, etc.

#### Example 3: Malicious APK Download

```bash
curl -X POST "http://localhost:8000/api/v1/analyze/url" \
  -H "Content-Type: application/json" \
  -d '{
    "url": "http://bad-domain.com/charging-app.apk"
  }'
```

**Expected Response:**
- `category`: "unknown_or_untrusted"
- `risk_score`: 80+ (high)
- `risk_level`: "high"
- `reasons`: Includes "Direct binary download detected (.apk)", "Using insecure HTTP"

### 2. QR Image Analysis - `POST /api/v1/analyze/qr-image`

Upload a QR code image for decoding and analysis.

#### Example with curl

```bash
# Upload a QR code image
curl -X POST "http://localhost:8000/api/v1/analyze/qr-image" \
  -F "file=@path/to/qr_code.png"
```

#### Example with HTTPie

```bash
http -f POST http://localhost:8000/api/v1/analyze/qr-image \
  file@path/to/qr_code.png
```

#### Example with Python requests

```python
import requests

url = "http://localhost:8000/api/v1/analyze/qr-image"

with open("qr_code.png", "rb") as f:
    files = {"file": f}
    response = requests.post(url, files=files)

print(response.json())
```

**Expected Response:**
```json
{
  "decoded_text": "https://example.com/charge/station123",
  "looks_like_url": true,
  "url_analysis": {
    "url": "https://example.com/charge/station123",
    "category": "unknown_or_untrusted",
    "risk_score": 35,
    "risk_level": "medium",
    "summary": {
      "short_verdict": "This domain is not recognized...",
      "recommended_action": "warn"
    },
    "content_inspection": { ... },
    "technical_details": { ... }
  },
  "qr_log_id": "uuid-here",
  "image_format": "PNG",
  "image_dimensions": "500x500"
}
```

## Response Structure

### URL Analysis Response

The response is structured to support a tabbed UI:

**Tab 1: Summary**
- `category`, `risk_score`, `risk_level`, `reasons`
- `summary.short_verdict`, `summary.recommended_action`

**Tab 2: Content Analysis**
- `content_inspection.title`, `meta_description`
- `content_inspection.script_count`, `form_count`, `iframe_count`
- `content_inspection.form_overview` (list of forms)
- `content_inspection.external_domains` (list of external sites)

**Tab 3: Technical Details**
- `technical_details.raw_headers`
- `technical_details.redirect_chain`
- `technical_details.final_url_after_redirects`
- `technical_details.fetch_time_ms`

**Tab 4: Log**
- `log_id` (for database lookup)
- `created_at` (timestamp)

## Testing the Risk Scoring Fix

The key improvement is that legitimate sites like Google are NO LONGER flagged as high-risk:

### Before (Old System)
```
URL: https://www.google.com
Result: "malicious" or "suspicious" (60-80+ score)
Reason: "Domain does not match official domain"
```

### After (New System)
```
URL: https://www.google.com
Result: "low" risk (5-15 score)
Category: "trusted_third_party"
Reason: "Domain is in trusted third-party list (Google)"
```

## API Documentation

Interactive API documentation available at:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc
