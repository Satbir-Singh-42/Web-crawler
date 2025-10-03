# 🕵️‍♂️ Phishing Domain Detector

A powerful Flask web application that detects phishing domains using AI and machine learning. Features Google Gemini API integration with ML model fallback for intelligent phishing detection with detailed risk assessment.

## ✨ Features

### Detection Capabilities
- 🔍 **AI-Powered Detection** - Google Gemini API analyzes domains with detailed reasoning
- 🤖 **ML Model Fallback** - RandomForest classifier for when API is unavailable
- 🔒 **SSL Certificate Validation** - Checks certificate validity and trusted CAs
- 📧 **Domain Authentication** - Validates DMARC, SPF, and DNS security records
- 🌐 **WHOIS Analysis** - Examines domain registration and age
- 📝 **Content Scanning** - Analyzes web content for phishing patterns
- 📊 **Batch Processing** - Upload Excel files to analyze multiple domains
- ⚡ **Real-time Analysis** - Multi-threaded concurrent scanning

## 🚀 Quick Start (Replit)

### 1. Install Dependencies (First Time Only)

If dependencies aren't installed, run in the Shell:
```bash
pip install -r requirements.txt
```

### 2. Environment Setup (Recommended)

For AI-powered detection, add your Google Gemini API key:

1. Click on **Secrets** (🔒 icon) in the left sidebar
2. Add a new secret:
   - Key: `GOOGLE_API_KEY`
   - Value: Your Google Gemini API key ([Get one here](https://makersuite.google.com/app/apikey))

**Note**: The app works without the API key using the ML model fallback, but Gemini provides more detailed analysis.

### 3. Run the Application

Click the **Run** button at the top. The app will:
- ✅ Load the ML model (phishing_model.pkl)
- ✅ Configure Google Gemini API (if key provided)
- ✅ Start Flask server on port 5000

### 4. Access the Web Interface

The web preview will open automatically showing the phishing detector interface.

## 📖 How to Use

### Web Interface

1. **Analyze Domain for Phishing Variations**
   - Enter a legitimate domain (e.g., `paypal.com`)
   - Click "Analyze Domain"
   - View potential phishing domains found

2. **Quick Domain Check**
   - Click "quick check a specific domain"
   - Enter the legitimate domain and domain to check
   - Get instant verification results

### API Endpoints

#### 1. AI-Powered Detection
```bash
curl -X POST https://your-repl-url.repl.co/ml-detect \
  -H "Content-Type: application/json" \
  -d '{"domain":"paypal-login-secure.com"}'
```

**Response:**
```json
{
  "domain": "paypal-login-secure.com",
  "is_phishing": true,
  "confidence": 95.0,
  "classification": "Phishing",
  "detection_method": "Google Gemini API",
  "reasons": [
    "Contains suspicious keywords 'login' and 'secure'",
    "Uses hyphens to imitate PayPal",
    "Not the official PayPal domain"
  ],
  "features": {
    "length": 23,
    "has_hyphen": 1,
    "suspicious_keywords": 1
  }
}
```

#### 2. Quick Domain Check
```bash
curl -X POST https://your-repl-url.repl.co/check-domain \
  -H "Content-Type: application/json" \
  -d '{"domain":"google.com", "target_domain":"google.com"}'
```

#### 3. Batch Detection (Excel Upload)
```bash
curl -X POST https://your-repl-url.repl.co/batch-detect \
  -F "file=@domains.xlsx"
```

Excel file should have a column named `domain` with one domain per row.

#### 4. Get Analysis Results
```bash
curl https://your-repl-url.repl.co/api/analysis/{analysis_id}
```

## 🔧 How It Works

### Detection Pipeline

1. **Domain Variation Generation**
   - Creates potential phishing domains using common patterns
   - Adds prefixes/suffixes: `login-`, `secure-`, `-verify`, etc.
   - Tests alternative TLDs: `.net`, `.org`, `.info`

2. **Multi-Layer Validation**
   - SSL certificate verification
   - DNS record analysis (DMARC, SPF)
   - WHOIS registration checks
   - Content scanning for login forms

3. **AI Analysis**
   - **Primary**: Google Gemini API analyzes domain structure and patterns
   - **Fallback**: ML model uses 8 features (length, digits, hyphens, keywords, etc.)
   - **Cross-Validation**: Both models compare results for reliability

4. **Risk Classification**
   - **High Risk**: Multiple red flags (invalid SSL, login forms, new domain)
   - **Medium Risk**: Some suspicious indicators
   - **Low Risk**: Minimal or no concerning patterns

## 📁 Project Structure

```
.
├── app.py                           # Main Flask application
├── phishing_model.pkl               # Trained ML model
├── kaggle_phishing_dataset.csv      # Dataset (549K+ records)
├── load_kaggle_dataset.py           # Utility to update dataset
├── requirements.txt                 # Python dependencies
├── .env.example                     # Environment variables template
├── templates/
│   ├── index.html                   # Main interface
│   └── results.html                 # Results display
└── README.md                        # This file
```

## 🔐 Environment Variables

Create a `.env` file or use Replit Secrets:

| Variable | Required | Description |
|----------|----------|-------------|
| `GOOGLE_API_KEY` | Yes | Google Gemini API key for AI detection |
| `SECRET_KEY` | Optional | Flask session secret (auto-generated if not set) |
| `KAGGLE_USERNAME` | Optional | For downloading/updating the dataset |
| `KAGGLE_KEY` | Optional | Kaggle API key for dataset access |

### Getting API Keys

**Google Gemini API:**
1. Go to [Google AI Studio](https://makersuite.google.com/app/apikey)
2. Click "Get API Key"
3. Create a new API key
4. Add to Replit Secrets as `GOOGLE_API_KEY`

**Kaggle API (Optional):**
1. Go to [Kaggle Account Settings](https://www.kaggle.com/account)
2. Scroll to "API" section
3. Click "Create New API Token"
4. Add credentials to Replit Secrets

## 🚢 Deployment

### Replit Deployment

1. Click the **Deploy** button in Replit
2. The app uses Gunicorn for production:
   - 4 workers for concurrent requests
   - 120-second timeout for long-running checks
   - Autoscale deployment for efficiency

### Configuration
- **Development**: Flask debug server on port 5000
- **Production**: Gunicorn WSGI server with autoscaling

## 📊 Dataset

The app includes a Kaggle phishing dataset with 549K+ records:
- Column `URL`: Domain/URL to check
- Column `Label`: `bad` (phishing) or `good` (legitimate)

To update the dataset:
```bash
python load_kaggle_dataset.py
```

## 🧪 Testing

### Test AI Detection
```bash
curl -X POST http://localhost:5000/ml-detect \
  -H "Content-Type: application/json" \
  -d '{"domain":"paypal-secure.com"}'
```

### Test Domain Analysis
1. Open the web interface
2. Enter a domain like `google.com`
3. Click "Analyze Domain"
4. View results showing potential phishing domains

## ⚙️ Technical Details

### Dependencies
- **Flask 2.3.3** - Web framework
- **Google Generative AI** - Gemini API integration
- **scikit-learn** - ML model (RandomForest)
- **pandas** - Data processing
- **dnspython** - DNS validation
- **python-whois** - Domain registration lookup
- **BeautifulSoup4** - HTML content analysis
- **jellyfish** - String similarity (Levenshtein distance)

### ML Model Features
1. Domain length
2. Has digits (0/1)
3. Has hyphens (0/1)
4. Number of dots
5. Number of digits
6. Suspicious keywords count
7. TLD length
8. Subdomain count

## 🔍 Troubleshooting

### "ML model loaded successfully" but Gemini API not working
- Check if `GOOGLE_API_KEY` is set in Replit Secrets
- Verify the API key is valid at [Google AI Studio](https://makersuite.google.com/app/apikey)
- The app will automatically use the ML model fallback

### Port 5000 already in use
- Replit automatically handles port assignment
- The app is configured to use `0.0.0.0:5000`

### LSP import warnings
- These are false positives from the language server
- All packages are installed and working correctly
- The app runs without any actual errors

### No results from domain analysis
- Check internet connection
- Some domains may not have existing variations
- Try a popular domain like `paypal.com` or `google.com`

## 📈 Performance

- **Analysis Time**: 5-15 seconds per domain
- **Concurrent Processing**: 5 worker threads
- **Dataset Size**: 549K+ phishing records
- **ML Model Accuracy**: High accuracy on test set
- **API Response**: < 2 seconds for detection

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Commit changes: `git commit -m 'Add feature'`
4. Push to branch: `git push origin feature-name`
5. Submit a pull request

## 📝 License

This project is open source and available under the MIT License.

## 👨‍💻 Author

Original Author: [param-punjab](https://github.com/param-punjab)

## 🙏 Acknowledgments

- Google Gemini API for AI-powered detection
- Kaggle for phishing datasets
- scikit-learn for ML capabilities
- Flask framework for web application

---

**Made for cybersecurity research and education** 🔒
