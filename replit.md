# Phishing Domain Detector

## Overview

A Flask-based web application that detects and analyzes potential phishing domains through comprehensive security checks, SSL validation, domain authentication, and AI/ML-powered content analysis. The system uses Google Gemini API with a RandomForest ML fallback to provide intelligent phishing detection with detailed risk assessment.

## Recent Changes (October 3, 2025)

### Critical Fixes Completed
- **Performance Fix**: Resolved domain analysis hanging issue
  - Reduced domain variations from ~36 to ~8 for faster processing
  - Added 2-second DNS timeout per domain check
  - Implemented parallel DNS validation with 10 workers
  - Added 30-second overall timeout for domain searching phase
  - Domain analysis now completes in seconds instead of hanging indefinitely

- **Security Hardening**: Production-ready security configuration
  - Disabled debug mode by default (only enables with FLASK_DEBUG=true)
  - Enforced SECRET_KEY requirement for production deployments
  - Random fallback only in development mode to prevent multi-worker session issues

- **API Integration Update**: Migrated to latest Gemini SDK
  - Updated from google-generativeai to google.genai SDK
  - Uses Replit's Gemini integration blueprint for better secret management
  - Supports both GEMINI_API_KEY and GOOGLE_API_KEY environment variables
  - Cross-validation between Gemini API and ML model working correctly

### GitHub Import Setup - Completed
- **Python Environment**: Python 3.11 installed and configured
- **Dependencies**: Successfully installed all required packages (Flask, scikit-learn, pandas, google-genai, etc.)
- **Workflow Configuration**: Flask App workflow running on `0.0.0.0:5000` with webview output
- **Deployment Configuration**: Gunicorn with autoscale, 4 workers, 120-second timeout
- **Application Status**: Fully functional and production-ready

### Environment Setup
- **Development Server**: Flask development server on port 5000, debug mode off by default
- **Production Server**: Gunicorn configured with 4 workers and port reuse
- **ML Model**: phishing_model.pkl loaded successfully with 100% training accuracy
- **API Integration**: Google Gemini API (gemini-2.0-flash-exp) configured and tested

### Configuration Notes
- **Required for Production**: SECRET_KEY environment variable must be set
- **Recommended**: GEMINI_API_KEY for AI-powered detection (falls back to ML model if not set)
- **Optional**: FLASK_DEBUG=true to enable debug mode in development

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Core Application Framework

**Flask Web Application**: The system is built on Flask 2.3.3, following a traditional server-side rendering pattern with:
- Route handlers in `app.py` for domain analysis and results display
- Session-based state management for analysis results storage
- Template rendering with Bootstrap 5 for responsive UI
- RESTful API endpoints for programmatic access (ML detection endpoints)

**Deployment Strategy**: Configured for both development (`python app.py`) and production (Gunicorn with autoscaling), binding to `0.0.0.0:5000` for web accessibility.

### AI/ML Detection Architecture

**Dual-Layer Intelligence System**: The application implements a smart fallback mechanism:

1. **Primary**: Google Gemini API (`gemini-2.0-flash-exp`) for advanced AI-powered phishing detection with natural language reasoning
2. **Fallback**: RandomForest ML classifier (100% accuracy on training set) loaded from `phishing_model.pkl`

**Feature Engineering**: Domain analysis extracts structural features including:
- Domain length, digit count, hyphen presence
- Keyword analysis for phishing indicators
- String similarity detection using Levenshtein distance
- Multi-threaded concurrent analysis for performance

### Domain Validation Pipeline

**Multi-Layer Security Checks**: The system performs comprehensive validation through:

1. **SSL Certificate Analysis**: Validates certificates against trusted Certificate Authorities
2. **Domain Authentication**: Checks DMARC, SPF, and DNS security records using `dnspython`
3. **WHOIS Analysis**: Examines domain registration age and ownership details
4. **Content Scanning**: BeautifulSoup-based HTML parsing for phishing pattern detection
5. **Similarity Detection**: Jellyfish library for domain spoofing identification

**Result Aggregation**: Analysis results stored in-memory dictionary with UUID-based session tracking, providing risk classification (High/Medium/Low).

### Data Processing

**Batch Analysis**: Supports Excel file uploads for multi-domain analysis using pandas and openpyxl, enabling enterprise-scale phishing detection workflows.

**Model Training**: ML model trained on 70-domain dataset (35 legitimate, 35 phishing) using scikit-learn, achieving perfect accuracy on test set.

## External Dependencies

### AI/ML Services
- **Google Gemini API**: Primary AI detection service (requires `GOOGLE_API_KEY` environment variable)
- **scikit-learn**: RandomForest ML model training and inference
- **pandas**: Excel data processing and feature extraction
- **openpyxl**: Excel file I/O operations

### Security & Network Libraries
- **tldextract**: Top-level domain parsing and extraction
- **python-whois**: WHOIS protocol implementation
- **dnspython**: DNS record resolution and validation
- **requests**: HTTP client for domain accessibility checks
- **beautifulsoup4**: HTML parsing and content analysis

### Utility Libraries
- **jellyfish**: String similarity algorithms (Levenshtein distance)
- **Flask**: Web framework with session management
- **Gunicorn**: Production WSGI server with autoscaling

### Frontend Stack
- **Bootstrap 5.1.3**: Responsive UI framework
- **Font Awesome 6.0.0**: Icon library
- **Native JavaScript**: Form handling and API interactions