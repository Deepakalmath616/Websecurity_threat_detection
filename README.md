# CyberShield — Integrated Web Security & Threat Detection System

A modern cybersecurity platform for detecting phishing URLs, analyzing password strength, scanning QR codes, and monitoring threats in real-time.

## 🚀 Features

- **Phishing URL Detection** — AI-powered analysis using Google Safe Browsing API
- **Password Strength Analyzer** — Entropy analysis with breach database checks
- **QR Threat Detection** — Scan QR codes for malicious payloads
- **Real-time Threat Monitoring** — Live threat intelligence feeds
- **Browser Extension Integration** — On-the-fly security checks
- **Security Score Dashboard** — Comprehensive security posture scoring

## 📁 Project Structure

```
cybershield/
├── frontend/              # Frontend web application
│   ├── index.html         # Home page
│   ├── phishing-detector.html  # URL checker page
│   ├── css/
│   │   ├── style.css      # Global styles
│   │   └── phishing-detector.css  # URL checker styles
│   ├── js/
│   │   ├── main.js        # Home page scripts
│   │   └── phishing-detector.js   # URL checker logic + API integration
│   └── assets/
│
└── backend/               # Flask backend API
    ├── app.py             # Main Flask application
    ├── requirements.txt   # Python dependencies
    └── .env.example       # Environment variables template
```

## 🛠️ Setup Instructions

### Backend Setup

**1. Install Python dependencies**
```bash
cd backend
pip install -r requirements.txt
```

**2. Get Google Safe Browsing API Key**
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project (or select existing)
3. Enable **Safe Browsing API** from the API Library
4. Go to **Credentials** → **Create Credentials** → **API Key**
5. Copy your API key

**3. Set environment variable**

Linux / Mac:
```bash
export GOOGLE_API_KEY="your_api_key_here"
```

Windows (CMD):
```cmd
set GOOGLE_API_KEY=your_api_key_here
```

Windows (PowerShell):
```powershell
$env:GOOGLE_API_KEY="your_api_key_here"
```

**4. Run the Flask server**
```bash
python app.py
```

Server starts at `http://127.0.0.1:5000`

> **Note:** The backend will run without an API key using mock responses for testing. Configure the API key for real threat detection.

### Frontend Setup

**Option 1: Open directly in browser**
- Navigate to `frontend/` folder
- Double-click `index.html`

**Option 2: Use Live Server (recommended for development)**
1. Install **Live Server** extension in VS Code
2. Right-click `frontend/index.html` → **Open with Live Server**
3. Browser opens at `http://127.0.0.1:5500`

**Option 3: Python HTTP server**
```bash
cd frontend
python -m http.server 8080
```
Open `http://localhost:8080` in your browser

**Option 4: Node.js serve**
```bash
npx serve frontend
```

## 🔗 API Endpoints

### POST `/check-url`
Check if a URL is safe or malicious.

**Request:**
```json
{
  "url": "https://example.com"
}
```

**Response (Safe):**
```json
{
  "status": "Safe ✅",
  "details": "No threats detected by Google Safe Browsing API.",
  "url": "https://example.com",
  "threat_type": null
}
```

**Response (Malicious):**
```json
{
  "status": "Phishing ❌",
  "details": "This URL is flagged as a phishing/social engineering site by Google Safe Browsing.",
  "url": "http://malicious-site.com",
  "threat_type": "SOCIAL_ENGINEERING"
}
```

### GET `/health`
Health check endpoint.

**Response:**
```json
{
  "status": "healthy",
  "service": "CyberShield Backend API",
  "version": "1.0.0",
  "api_key_configured": true
}
```

### GET `/`
API documentation endpoint.

## 🧪 Testing

**Test with safe URL:**
```bash
curl -X POST http://127.0.0.1:5000/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "https://google.com"}'
```

**Test with Google's malware test URL:**
```bash
curl -X POST http://127.0.0.1:5000/check-url \
  -H "Content-Type: application/json" \
  -d '{"url": "http://malware.testing.google.test/testing/malware/"}'
```

## 🎨 Frontend Features

### Home Page (`index.html`)
- Animated matrix rain background
- Hero section with typing animation
- 6 feature cards with hover effects
- About section with tech stack badges
- Animated statistics counters
- Responsive design (mobile-first)

### URL Checker Page (`phishing-detector.html`)
- Real-time URL analysis
- Loading animation with progress indicators
- Threat status visualization
- Security score ring (0-100)
- Threat level gradient bar
- URL breakdown (protocol, domain, path, query)
- Threat type badge (Malware, Phishing, etc.)
- Recommendations based on threat level
- Copy report to clipboard
- Demo URLs for testing
- Error handling with troubleshooting tips

## 🔧 Technology Stack

**Frontend:**
- HTML5
- CSS3 (Custom properties, animations, grid, flexbox)
- Vanilla JavaScript (ES6+)
- Fetch API for backend communication

**Backend:**
- Python 3.x
- Flask (web framework)
- Flask-CORS (cross-origin requests)
- Requests (HTTP library)
- Google Safe Browsing API v4

## 🛡️ Security Features

### URL Analysis
- **Google Safe Browsing** — Real-time threat detection
- **Client-side heuristics** — HTTPS check, IP detection, suspicious TLDs
- **Threat classification** — Malware, Phishing, Unwanted Software, Potentially Harmful
- **Security scoring** — 0-100 score based on multiple signals

### Error Handling
- Network failures
- API timeouts (10s)
- Rate limiting
- Invalid URLs
- Server errors
- CORS issues

## 📊 Threat Types

| Type | Description | Score Range |
|------|-------------|-------------|
| **Safe** | No threats detected | 70-100 |
| **Suspicious** | Unwanted software or potentially harmful | 30-69 |
| **Danger** | Malware or phishing confirmed | 0-29 |

### Google Safe Browsing Threat Types
- `MALWARE` — Malicious software
- `SOCIAL_ENGINEERING` — Phishing/social engineering
- `UNWANTED_SOFTWARE` — Unwanted software
- `POTENTIALLY_HARMFUL_APPLICATION` — Potentially harmful apps

## 🎯 Usage

1. **Start the backend:**
   ```bash
   cd backend
   python app.py
   ```

2. **Open the frontend:**
   - Navigate to `http://127.0.0.1:5500` (Live Server)
   - Or open `frontend/index.html` directly

3. **Test URL detection:**
   - Click "URL Checker" in the navigation
   - Enter a URL or select a demo URL
   - Click "Scan URL"
   - View the detailed threat analysis

## 🐛 Troubleshooting

### Backend not starting
- Check Python version: `python --version` (requires 3.7+)
- Install dependencies: `pip install -r requirements.txt`
- Verify Flask is installed: `pip show flask`

### CORS errors in browser
- Ensure `flask-cors` is installed: `pip install flask-cors`
- Check Flask terminal for CORS-related errors
- Verify backend is running on port 5000

### API key issues
- Verify environment variable is set: `echo $GOOGLE_API_KEY`
- Check API key is valid in Google Cloud Console
- Ensure Safe Browsing API is enabled for your project

### Frontend not connecting to backend
- Verify backend is running: `curl http://127.0.0.1:5000/health`
- Check browser console (F12) for error messages
- Ensure no firewall is blocking port 5000

## 📝 License

This project is open source and available under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📧 Contact

For questions or support, please open an issue on GitHub.

---

**Built with ❤️ for a safer internet.**
