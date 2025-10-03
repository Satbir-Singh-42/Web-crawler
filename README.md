# 🕵️‍♂️ Advanced Phishing Domain Detector

A powerful Flask-based web application that detects and analyzes potential phishing domains by performing comprehensive security checks, SSL validation, domain authentication, content analysis, and AI-powered phishing detection using Google Gemini API with ML model fallback.

## 🌟 Features

### Core Detection Features
- **Domain Legitimacy Verification**: Multi-layered domain validation
- **SSL Certificate Analysis**: Validates SSL certificates from trusted CAs
- **Domain Authentication**: Checks DMARC, SPF, and security records
- **WHOIS Analysis**: Examines domain registration details and age
- **Content Scanning**: Analyzes web content for phishing indicators
- **Similarity Detection**: Uses Levenshtein distance to identify domain spoofing
- **Real-time Analysis**: Multi-threaded scanning for efficient detection
- **Risk Assessment**: Classifies domains as High, Medium, or Low risk

### AI/ML-Powered Features
- **Google Gemini API Integration**: Advanced AI-powered phishing detection with detailed reasoning
- **ML Model Fallback**: RandomForest classifier (100% accuracy) when API unavailable
- **Batch Processing**: Upload Excel files to analyze multiple domains
- **Feature Extraction**: Analyzes domain length, digits, hyphens, keywords, and structure
- **Smart Fallback System**: Automatically switches between Gemini API → ML model based on availability

## 📋 Prerequisites

- Python 3.11+
- pip (Python package manager)
- Internet connection for domain checking
- (Optional) Google Gemini API key for AI-powered detection

## 🚀 Quick Start

### Installation (Linux/macOS/Windows)

1. **Clone the repository**:
   ```bash
   git clone https://github.com/param-punjab/web-crawler
   cd web-crawler
   ```

2. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

3. **(Optional)** Set up Google Gemini API:
   ```bash
   export GOOGLE_API_KEY="your-api-key-here"
   ```

4. **Run the application**:
   ```bash
   python app.py
   ```

5. **Access the app**: Open `http://localhost:5000` in your browser

## 📊 Dependencies

```txt
Flask==2.3.3
tldextract==3.4.4
beautifulsoup4==4.12.2
requests==2.31.0
python-whois==0.8.0
dnspython==2.4.2
jellyfish==1.0.3
whois
gunicorn
openpyxl
pandas
scikit-learn
google-generativeai
```

## 🎯 Usage

### Web Interface

1. **Traditional Domain Analysis**:
   - Enter a target domain (e.g., `google.com`)
   - Click "Analyze Domain" to start detection
   - View results showing potential phishing domains
   - Export results as JSON or CSV

2. **Quick Domain Check**:
   - Click "quick check a specific domain"
   - Enter legitimate domain and domain to check
   - Get instant legitimacy verification

### API Endpoints (Programmatic Access)

The application provides REST API endpoints for programmatic access:

#### 1. Start Domain Analysis
```bash
curl -X POST http://localhost:5000/analyze \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "domain=example.com"
```

#### 2. AI-Powered Phishing Detection
```bash
curl -X POST http://localhost:5000/ml-detect \
  -H "Content-Type: application/json" \
  -d '{"domain":"paypal-secure.com"}'
```

Response:
```json
{
  "classification": "Phishing",
  "confidence": 95.0,
  "detection_method": "Google Gemini API",
  "domain": "paypal-secure.com",
  "is_phishing": true,
  "reasons": [
    "Contains the keyword 'secure', frequently used in phishing",
    "Not the official PayPal domain",
    "Uses hyphen to imitate legitimate services"
  ],
  "features": {
    "length": 17,
    "has_hyphen": 1,
    "suspicious_keywords": 1
  }
}
```

#### 3. Quick Domain Legitimacy Check
```bash
curl -X POST http://localhost:5000/check-domain \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com", "target_domain":"google.com"}'
```

#### 4. Batch Detection from Excel
```bash
curl -X POST http://localhost:5000/batch-detect \
  -F "file=@domains.xlsx"
```

#### 5. Get Analysis Results
```bash
curl http://localhost:5000/api/analysis/{analysis_id}
```

## 🔍 Detection Methods

The tool uses multiple techniques to identify phishing domains:

1. **Domain Variation Generation**: Creates potential phishing domains using common patterns (prefixes, suffixes, TLD changes)
2. **SSL Certificate Validation**: Checks certificate validity, expiration, and organization details
3. **DNS Record Analysis**: Validates security records (DMARC, SPF)
4. **WHOIS Verification**: Examines domain registration information and age
5. **Content Analysis**: Scans for login forms and suspicious keywords
6. **Similarity Comparison**: Measures textual similarity using Levenshtein distance
7. **AI-Powered Detection**: Google Gemini API analyzes domains with detailed reasoning
8. **ML Model Classification**: RandomForest model as fallback with feature extraction

## 📁 Project Structure

```
.
├── app.py                 # Main Flask application with all endpoints
├── phishing_model.pkl     # Trained RandomForest ML model (100% accuracy)
├── domain_dataset.xlsx    # Training dataset (70 domains: 35 legitimate + 35 phishing)
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore rules
├── README.md             # This file
├── DOCUMENTATION.md      # Technical documentation
└── templates/            # HTML templates
    ├── index.html        # Main interface
    └── results.html      # Results display
```

## 🚢 Deployment

### Production Deployment

For production environments, use Gunicorn WSGI server:

```bash
gunicorn --bind=0.0.0.0:5000 --workers=4 app:app
```

**Recommended Configuration**:
- Workers: 2-4 (based on CPU cores)
- Port: 5000
- Timeout: 120 seconds (for long-running domain checks)
- Use reverse proxy (Nginx/Apache) for SSL termination

## ⚙️ Configuration

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_API_KEY` | Optional | Google Gemini API key for AI-powered detection. If not set, falls back to ML model |

### Development vs Production

**Development** (default when running `python app.py`):
- Debug mode: Enabled
- Host: 0.0.0.0
- Port: 5000
- Auto-reload: Enabled

**Production** (when using Gunicorn):
- Debug mode: Disabled
- Workers: 4
- Host: 0.0.0.0
- Port: 5000

## 🔐 Security Considerations

- Application performs network requests to external domains
- SSL verification is enabled by default
- User input is sanitized before processing
- Session management uses Flask's built-in secret key (change in production!)
- Google Gemini API key stored in environment variables (never hardcoded)

## ⚡ Troubleshooting

### Common Issues

**1. ML model not loading:**
- Ensure `phishing_model.pkl` file exists in project root
- Check Python version (requires 3.11+)

**2. Google Gemini API not working:**
- Verify `GOOGLE_API_KEY` environment variable is set
- Check API key is valid and has quota
- System automatically falls back to ML model if API unavailable

**3. Domain analysis returns no results:**
- Check internet connection
- Verify DNS resolution is working
- Some domains may not have variations that exist

**4. Port 5000 already in use:**
- Change port in `app.py`: `app.run(port=5001)`
- Or kill process using port 5000: `lsof -ti:5000 | xargs kill`

**5. Dependencies installation fails:**
- Update pip: `pip install --upgrade pip`
- Install build tools: `apt-get install python3-dev` (Linux)

## 🧪 Testing

### Test the Application

1. **Test Frontend**: Open `http://localhost:5000` and analyze a domain
2. **Test ML Endpoint**: 
   ```bash
   curl -X POST http://localhost:5000/ml-detect \
     -H "Content-Type: application/json" \
     -d '{"domain":"test.com"}'
   ```
3. **Test Quick Check**:
   ```bash
   curl -X POST http://localhost:5000/check-domain \
     -H "Content-Type: application/json" \
     -d '{"domain":"google.com","target_domain":"google.com"}'
   ```

### Verify Gemini API Integration

```bash
curl -X POST http://localhost:5000/ml-detect \
  -H "Content-Type: application/json" \
  -d '{"domain":"paypal-login.com"}'
```

Look for `"detection_method": "Google Gemini API"` in response.

## 📈 Performance

- **Average Analysis Time**: 5-15 seconds per target domain
- **Concurrent Analysis**: Multi-threaded (5 workers)
- **Domain Variations**: Generates 40+ potential phishing domains
- **ML Model Accuracy**: 100% on test dataset (70 domains)
- **API Response Time**: < 2 seconds for ML detection

## 🛣️ Roadmap

- [ ] Database storage for analysis history
- [ ] User authentication and session management
- [ ] Scheduled scanning for monitored domains
- [ ] Email alerts for detected phishing domains
- [ ] API rate limiting and caching
- [ ] Enhanced AI model training with larger datasets
- [ ] Support for bulk domain list uploads (CSV)
- [ ] Domain reputation scoring system
- [ ] Integration with threat intelligence feeds

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Make your changes and commit: `git commit -m 'Add feature'`
4. Push to the branch: `git push origin feature-name`
5. Submit a pull request

## 📝 License

This project is open source and available under the MIT License.

## 👥 Authors

- **Original Author**: [param-punjab](https://github.com/param-punjab)

## 🙏 Acknowledgments

- Google Gemini API for AI-powered phishing detection
- scikit-learn for machine learning capabilities
- Flask framework for web application
- Bootstrap for responsive UI design

## 📧 Support

**For support:**
- Create an issue on GitHub with details about your problem
- Include error messages, logs, and steps to reproduce
- Check existing issues first to avoid duplicates

---

**Made with ❤️ for cybersecurity**
