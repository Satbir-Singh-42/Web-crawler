# Advanced Phishing Domain Detector

## Overview
This is a Flask-based web application that detects and analyzes potential phishing domains by performing comprehensive security checks, SSL validation, domain authentication, and content analysis. The tool helps identify websites that may be mimicking legitimate domains for malicious purposes.

## Recent Changes
- **October 2, 2025**: Imported and configured project for Replit environment
  - Configured Flask to bind to 0.0.0.0:5000
  - Set up workflow for development server
  - Installed all Python dependencies
  - Configured deployment with Gunicorn for production
  - Created .gitignore for Python projects

## Project Architecture

### Technology Stack
- **Backend**: Python 3.11 + Flask 2.3.3
- **Libraries**:
  - `tldextract`: Domain parsing and extraction
  - `beautifulsoup4`: HTML parsing and content analysis
  - `requests`: HTTP requests for domain checking
  - `python-whois`: WHOIS information retrieval
  - `dnspython`: DNS record validation
  - `jellyfish`: String similarity analysis (Levenshtein distance)

### Key Features
1. **Domain Legitimacy Verification**: Multi-layered domain validation
2. **SSL Certificate Analysis**: Validates SSL certificates from trusted CAs
3. **Domain Authentication**: Checks DMARC, SPF, and security records
4. **WHOIS Analysis**: Examines domain registration details and age
5. **Content Scanning**: Analyzes web content for phishing indicators
6. **Similarity Detection**: Identifies domain spoofing using Levenshtein distance
7. **Real-time Analysis**: Multi-threaded scanning for efficient detection
8. **Risk Assessment**: Classifies domains as High, Medium, or Low risk

### Project Structure
```
.
├── app.py                 # Main Flask application
├── templates/             # HTML templates
│   ├── index.html        # Main interface
│   └── results.html      # Results display
├── requirements.txt       # Python dependencies
├── .gitignore            # Git ignore rules
└── replit.md             # Project documentation
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
1. Enter a target domain (e.g., `google.com`)
2. Click "Analyze Domain" to start detection
3. View results showing potential phishing domains
4. Export results as JSON or CSV
5. Use "Quick Check" for single domain verification

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
- Machine learning for improved detection
- API rate limiting and caching
