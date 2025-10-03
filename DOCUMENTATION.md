# Advanced Phishing Domain Detector

## Overview
This is a Flask-based web application that detects and analyzes potential phishing domains by performing comprehensive security checks, SSL validation, domain authentication, and content analysis. The tool helps identify websites that may be mimicking legitimate domains for malicious purposes.

## Recent Changes
- **October 2, 2025**: Removed ML-Powered Detection UI from frontend (backend endpoints remain)
  - Removed ML-Powered Detection section from frontend interface
  - Backend ML endpoints (/ml-detect, /batch-detect) still available for programmatic access
  - Google Gemini API and ML model fallback system remain functional in backend
  
- **October 2, 2025**: Initial deployment setup
  - Installed Python 3.11 and all dependencies from requirements.txt
  - Configured Flask to bind to 0.0.0.0:5000 for web deployment
  - Set up development workflow with `python app.py`
  - Configured deployment with Gunicorn for production (autoscale)
  - Verified .gitignore for Python project
  
- **Previous**: Integrated Google Gemini API with ML fallback system
  - Added Google Gemini AI for phishing domain detection
  - Implemented fallback mechanism: Gemini API → ML model when API unavailable/quota exceeded
  - Created Excel dataset with 70 domains (35 legitimate + 35 phishing)
  - Trained RandomForest ML model achieving 100% accuracy

## Project Architecture

### Technology Stack
- **Backend**: Python 3.11 + Flask 2.3.3
- **AI/ML**:
  - `google-generativeai`: Google Gemini API for AI-powered phishing detection
  - `scikit-learn`: RandomForest ML model (100% accuracy on test set)
  - `pandas`: Data processing and Excel file handling
  - `openpyxl`: Excel file operations
- **Security Libraries**:
  - `tldextract`: Domain parsing and extraction
  - `beautifulsoup4`: HTML parsing and content analysis
  - `requests`: HTTP requests for domain checking
  - `python-whois`: WHOIS information retrieval
  - `dnspython`: DNS record validation
  - `jellyfish`: String similarity analysis (Levenshtein distance)

### Key Features
1. **AI-Powered Detection**: Google Gemini API for intelligent phishing analysis
2. **ML Model Fallback**: RandomForest classifier with 100% accuracy when API unavailable
3. **Domain Legitimacy Verification**: Multi-layered domain validation
4. **SSL Certificate Analysis**: Validates SSL certificates from trusted CAs
5. **Domain Authentication**: Checks DMARC, SPF, and security records
6. **WHOIS Analysis**: Examines domain registration details and age
7. **Content Scanning**: Analyzes web content for phishing indicators
8. **Similarity Detection**: Identifies domain spoofing using Levenshtein distance
9. **Batch Processing**: Upload Excel files to analyze multiple domains
10. **Real-time Analysis**: Multi-threaded scanning for efficient detection
11. **Risk Assessment**: Classifies domains as High, Medium, or Low risk

### Project Structure
```
.
├── app.py                 # Main Flask application
├── phishing_model.pkl     # Trained RandomForest ML model
├── domain_dataset.xlsx    # Training dataset (70 domains)
├── templates/             # HTML templates
│   ├── index.html        # Main interface
│   └── results.html      # Results display
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore rules
└── DOCUMENTATION.md      # Technical documentation
```

### Core Components

#### AdvancedDomainChecker Class
Responsible for domain legitimacy verification:
- SSL certificate validation
- Domain authentication (DMARC/SPF records)
- WHOIS registration checks

#### PhishingDetector Class
Handles phishing detection:
- Generates domain variations (common phishing patterns)
- Validates domain existence via DNS
- Analyzes content for phishing indicators
- Calculates risk levels

### API Endpoints
- `GET /`: Main interface
- `POST /analyze`: Start domain analysis
- `GET /results/<analysis_id>`: View analysis results
- `GET /api/analysis/<analysis_id>`: Get analysis data (JSON)
- `POST /check-domain`: Quick domain legitimacy check
- `POST /ml-detect`: AI-powered phishing detection (backend only - Gemini → ML fallback)
- `POST /batch-detect`: Batch domain analysis from Excel files (backend only)

### Configuration

#### Development
- Server runs on port 5000
- Debug mode enabled
- Threaded mode for concurrent requests
- Workflow: `python app.py`

#### Production
- Uses Gunicorn WSGI server
- 4 worker processes
- Deployment target: autoscale
- Command: `gunicorn --bind=0.0.0.0:5000 --reuse-port --workers=4 app:app`

## Security Considerations
- Application performs network requests to external domains
- SSL verification is enabled by default
- User input is sanitized before processing
- Session management uses Flask's built-in secret key (should be changed in production)

## Usage

### Web Interface
1. Enter a target domain (e.g., `google.com`)
2. Click "Analyze Domain" to start detection
3. View results showing potential phishing domains
4. Export results as JSON or CSV
5. Use "Quick Check" for single domain verification

### Backend API Access (Programmatic)
The ML-powered detection endpoints are available for programmatic access:

1. **Single Domain Check** (`POST /ml-detect`):
   ```bash
   curl -X POST http://localhost:5000/ml-detect \
     -H "Content-Type: application/json" \
     -d '{"domain":"example.com"}'
   ```
   - System tries Gemini API first, falls back to ML model if unavailable
   - Returns classification, confidence score, and AI reasoning

2. **Batch Detection** (`POST /batch-detect`):
   - Upload an Excel file with a "domain" column
   - Returns analysis results for all domains with detection method used

## Known Limitations
- Analysis depends on network availability
- Some legitimate domains may trigger false positives
- WHOIS data may not be available for all domains
- DNS resolution timeouts may occur
- Rate limiting may affect large-scale scans

## Future Enhancements
- Database storage for analysis history
- User authentication and session management
- Scheduled scanning for monitored domains
- Email alerts for detected phishing domains
- API rate limiting and caching
- Enhanced AI model training with more diverse datasets
