# Phishing Domain Detector

## Overview

A Flask-based web application that detects and analyzes potential phishing domains through comprehensive security checks, SSL validation, domain authentication, and AI/ML-powered content analysis. The system uses Google Gemini API with a RandomForest ML fallback to provide intelligent phishing detection with detailed risk assessment.

## Recent Changes (October 3, 2025)

### GitHub Import Setup - Completed
- **Python Environment**: Python 3.11 installed and configured
- **Dependencies**: Successfully installed all required packages from requirements.txt (Flask, scikit-learn, pandas, google-generativeai, and all other dependencies)
- **Requirements Cleanup**: Removed duplicate entries from requirements.txt for cleaner package management
- **Workflow Configuration**: Set up Flask App workflow to run on `0.0.0.0:5000` with webview output
- **Deployment Configuration**: Configured production deployment with Gunicorn using autoscale deployment target with 4 workers and 120-second timeout
- **Application Status**: Successfully running and tested - frontend loads correctly

### Environment Setup
- **Development Server**: Flask development server running on port 5000 with debug mode enabled
- **Production Server**: Gunicorn configured with 4 workers, port reuse, and extended timeout for long-running domain checks
- **ML Model**: phishing_model.pkl loaded successfully on startup
- **API Integration**: Google Gemini API ready (requires GOOGLE_API_KEY environment variable to be set by user)

### Configuration Notes
- To use Google Gemini API for advanced AI-powered detection, add GOOGLE_API_KEY to environment variables
- Without API key, application automatically falls back to RandomForest ML model

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