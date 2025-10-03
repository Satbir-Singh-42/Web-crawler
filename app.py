from flask import Flask, render_template, request, jsonify, session, redirect, url_for
import tldextract
import ssl
import socket
from datetime import datetime
import whois
import requests
import re
import dns.resolver
import threading
import uuid
import concurrent.futures
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin
import jellyfish
import pickle
import pandas as pd
import os
from google import genai
from google.genai import types
lev_distance = jellyfish.levenshtein_distance

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'dev-secret-key-change-in-production') 

analysis_results = {}

try:
    with open('phishing_model.pkl', 'rb') as f:
        ml_model = pickle.load(f)
    print("ML model loaded successfully")
except Exception as e:
    print(f"Warning: Could not load ML model: {e}")
    ml_model = None

try:
    api_key = os.environ.get('GEMINI_API_KEY') or os.environ.get('GOOGLE_API_KEY')
    if api_key:
        gemini_client = genai.Client(api_key=api_key)
        print("Google Gemini API configured successfully")
    else:
        gemini_client = None
        print("Warning: GEMINI_API_KEY not found in environment variables")
except Exception as e:
    print(f"Warning: Could not configure Gemini API: {e}")
    gemini_client = None

def extract_ml_features(domain):
    """Extract features from domain for ML model"""
    features = {}
    features['length'] = len(domain)
    features['has_digit'] = int(bool(re.search(r'\d', domain)))
    features['has_hyphen'] = int('-' in domain)
    features['num_dots'] = domain.count('.')
    features['num_digits'] = sum(c.isdigit() for c in domain)
    features['suspicious_keywords'] = int(any(kw in domain.lower() for kw in ['login', 'verify', 'secure', 'account', 'update', 'confirm']))
    features['tld_length'] = len(domain.split('.')[-1]) if '.' in domain else 0
    features['subdomain_count'] = domain.count('.') - 1 if domain.count('.') > 0 else 0
    return features

def validate_gemini_response(result):
    """Validate Gemini API response structure and data"""
    if not isinstance(result, dict):
        return False, "Response is not a dictionary"
    
    required_fields = ['is_phishing', 'confidence', 'reasons', 'classification']
    for field in required_fields:
        if field not in result:
            return False, f"Missing required field: {field}"
    
    if not isinstance(result['is_phishing'], bool):
        return False, "is_phishing must be a boolean"
    
    if not isinstance(result['confidence'], (int, float)):
        return False, "confidence must be a number"
    
    if not (0 <= result['confidence'] <= 100):
        return False, "confidence must be between 0 and 100"
    
    if not isinstance(result['reasons'], list):
        return False, "reasons must be a list"
    
    if not result['reasons']:
        return False, "reasons list cannot be empty"
    
    if result['classification'] not in ['Phishing', 'Legitimate']:
        return False, f"Invalid classification: {result['classification']}"
    
    is_phishing_matches = (result['is_phishing'] and result['classification'] == 'Phishing') or \
                          (not result['is_phishing'] and result['classification'] == 'Legitimate')
    if not is_phishing_matches:
        return False, "is_phishing and classification fields don't match"
    
    return True, "Valid"

def check_with_gemini(domain):
    """Check domain credibility using Google Gemini API with comprehensive validation"""
    if not gemini_client:
        return None, "Gemini API not available"
    
    try:
        prompt = f"""Analyze this domain for phishing indicators: {domain}

Please evaluate if this domain is legitimate or potentially a phishing domain. Consider:
1. Character substitutions (like 0 for O, 1 for l)
2. Suspicious keywords (login, verify, secure, account)
3. Domain structure and patterns
4. Known legitimate domains
5. TLD (top-level domain) reputation

Respond ONLY in valid JSON format with:
{{
  "is_phishing": true/false,
  "confidence": 0-100,
  "reasons": ["reason1", "reason2", "reason3"],
  "classification": "Phishing" or "Legitimate"
}}

Important: Provide at least 2-3 specific reasons for your classification."""

        response = gemini_client.models.generate_content(
            model='gemini-2.0-flash-exp',
            contents=prompt
        )
        
        if not response or not response.text:
            return None, "Empty response from Gemini API"
        
        import json
        result_text = response.text.strip()
        
        if result_text.startswith('```json'):
            result_text = result_text[7:-3].strip()
        elif result_text.startswith('```'):
            result_text = result_text[3:-3].strip()
        
        try:
            result = json.loads(result_text)
        except json.JSONDecodeError as je:
            return None, f"Invalid JSON response: {str(je)}"
        
        is_valid, validation_msg = validate_gemini_response(result)
        if not is_valid:
            return None, f"Invalid response format: {validation_msg}"
        
        print(f"✓ Gemini API validated: {domain} -> {result['classification']} ({result['confidence']}%)")
        return result, None
        
    except Exception as e:
        error_msg = str(e)
        if 'quota' in error_msg.lower() or 'rate' in error_msg.lower():
            return None, f"API quota exceeded: {error_msg}"
        elif 'api key' in error_msg.lower():
            return None, "Invalid API key"
        return None, f"API error: {error_msg}"

class AdvancedDomainChecker:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.target_parts = tldextract.extract(self.target_domain)
        
    def is_legitimate_domain(self, domain):
        """Check the domain legitimacy using multiple verification methods"""
        check_score = 0
        reasons = []
        
        parts = tldextract.extract(domain)

        if parts.registered_domain != self.target_parts.registered_domain:
            check_score += 1
            reasons.append("Different registered domain")
        
        ssl_valid, ssl_reason = self.has_valid_ssl_certificate(domain)
        if not ssl_valid:
            check_score += 1
            reasons.append(f"SSL Issue: {ssl_reason}")
        
        auth_valid, auth_reason = self.has_domain_authentication(parts.registered_domain)
        if not auth_valid:
            check_score += 1
            reasons.append(f"Domain auth issue: {auth_reason}")

        registration_valid, reg_reason = self.has_legitimate_registration(domain)
        if not registration_valid:
            check_score += 1
            reasons.append(f"Registration issue: {reg_reason}")
        
        if check_score == 0:
            return True, "Domain appears legitimate"
        else:
            return False, "; ".join(reasons)
            
    def has_valid_ssl_certificate(self, domain, port=443):
        """Check if the domain has valid SSL certificate from trusted CA"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()

                if not cert:
                    return False, "No SSL certificate found"
                
                not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                if datetime.now() > not_after:
                    return False, "SSL certificate expired"

                org_name = None
                if 'subject' in cert:
                    for field in cert['subject']:
                        if field[0][0] == 'organizationName':
                            org_name = field[0][1]
                            break

                if org_name and ("education" in org_name.lower() or "college" in org_name.lower() 
                                or "university" in org_name.lower() or "gndec" in org_name.lower()):
                    return True, f"Valid educational certificate: {org_name}"
                
                return True, "Valid SSL certificate"
        except Exception as e:
            return False, f"SSL connection failed: {str(e)}"
    
    def has_domain_authentication(self, domain):
        """Check for domain authentication records that legitimate organizations typically implement"""
        try:
            dmarc_record = f"_dmarc.{domain}"
            try:
                answers = dns.resolver.resolve(dmarc_record, 'TXT')
                for rdata in answers:
                    if 'v=DMARC1' in str(rdata):
                        return True, "DMARC record found"
            except:
                pass

            try:
                answers = dns.resolver.resolve(domain, 'TXT')
                for rdata in answers:
                    if 'v=spf1' in str(rdata):
                        return True, "SPF record found"
            except:
                pass

            return False, "No domain authentication records found"
        except Exception as e:
            return False, f"DNS checks failed: {str(e)}"
    
    def has_legitimate_registration(self, domain):
        """Check WHOIS information for legitimate registration details"""
        try:
            w = whois.whois(domain)
            
            if w.creation_date:
                if isinstance(w.creation_date, list):
                    creation_date = w.creation_date[0]
                else:
                    creation_date = w.creation_date

                if isinstance(creation_date, str):
                    try:
                        creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d %H:%M:%S')
                    except:
                        try:
                            creation_date = datetime.strptime(str(creation_date), '%d-%b-%Y')
                        except:
                            return True, "Could not parse creation date"
                elif not isinstance(creation_date, datetime):
                    return True, "Could not parse creation date"

                domain_age = (datetime.now() - creation_date).days
                if domain_age < 30:
                    return False, f"Domain is very new ({domain_age} days)"

            if domain.endswith('.edu') or domain.endswith('.ac.in'):
                return True, "Educational domain detected"

            return True, "Domain registration appears legitimate"
        except Exception as e:
            return False, f"WHOIS check failed: {str(e)}"

class PhishingDetector:
    def __init__(self, target_domain):
        self.target_domain = target_domain
        self.checker = AdvancedDomainChecker(target_domain)
        self.user_agent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": self.user_agent})
        
    def generate_domain_variations(self):
        """Generate potential phishing domains using various techniques"""
        variations = set()
        domain_parts = tldextract.extract(self.target_domain)
        base_domain = f"{domain_parts.domain}.{domain_parts.suffix}"
        
        prefixes = ['login', 'secure', 'account']
        suffixes = ['login', 'secure', 'verify']
        
        for prefix in prefixes:
            variations.add(f"{prefix}-{base_domain}")
            
        for suffix in suffixes:
            variations.add(f"{base_domain}-{suffix}")
            
        if domain_parts.suffix == 'com':
            for tld in ['net', 'org']:
                variations.add(f"{domain_parts.domain}.{tld}")
                
        return variations
        
    def get_suspicious_domains(self):
        """Get all suspicious domains from various sources"""
        print("Searching for suspicious domains...")
        
        generated_domains = self.generate_domain_variations()
        print(f"Generated {len(generated_domains)} domain variations")
        
        valid_domains = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
            future_to_domain = {executor.submit(self.validate_domain_exists, domain): domain for domain in generated_domains}
            
            for future in concurrent.futures.as_completed(future_to_domain, timeout=30):
                domain = future_to_domain[future]
                try:
                    if future.result():
                        valid_domains.append(domain)
                        print(f"Found valid domain: {domain}")
                except Exception as e:
                    pass
                
        print(f"Found {len(valid_domains)} valid domains to check")
        return valid_domains
        
    def validate_domain_exists(self, domain):
        """Check if a domain actually exists by resolving DNS"""
        try:
            resolver = dns.resolver.Resolver()
            resolver.timeout = 2
            resolver.lifetime = 2
            resolver.resolve(domain, 'A')
            return True
        except:
            return False
            
    def analyze_domain(self, domain):
        """Analyze a single domain for phishing indicators"""
        risk_factors = []
        final_url = domain
        title = ""
        
        is_legitimate, reason = self.checker.is_legitimate_domain(domain)
        if not is_legitimate:
            risk_factors.append(f"Legitimacy check failed: {reason}")
        
        try:
            response = self.session.get(f"https://{domain}", timeout=10, allow_redirects=True)
            final_url = response.url
            content = response.text
            
            soup = BeautifulSoup(content, 'html.parser')
            
            title_tag = soup.find('title')
            if title_tag:
                title = title_tag.get_text().strip()
                
            login_forms = soup.find_all('form')
            for form in login_forms:
                inputs = form.find_all('input')
                has_password = any(input.get('type') == 'password' for input in inputs)
                has_username = any(input.get('type') in ['text', 'email'] for input in inputs)
                
                if has_password and has_username:
                    risk_factors.append("Contains login form with username and password fields")
                    break
            
            suspicious_keywords = ['login', 'signin', 'verify', 'account', 'security']
            content_lower = content.lower()
            
            if title:
                title_lower = title.lower()
                if any(keyword in title_lower for keyword in suspicious_keywords):
                    risk_factors.append("Uses suspicious keywords in title")
            
            keyword_count = 0
            for keyword in suspicious_keywords:
                if keyword in content_lower:
                    keyword_count += 1
            
            if keyword_count > 3:
                risk_factors.append(f"Uses multiple ({keyword_count}) suspicious keywords in content")
                
            target_clean = self.target_domain.replace('www.', '').replace('.com', '')
            domain_clean = domain.replace('www.', '').replace('.com', '')
            
            similarity = lev_distance(target_clean, domain_clean)
            if similarity <= 2:
                risk_factors.append(f"Very similar to target domain (distance: {similarity})")
                
        except Exception as e:
            risk_factors.append(f"Cannot access website: {str(e)}")
        
        risk_level = self.determine_risk_level(risk_factors)
        
        return risk_factors, final_url, title, risk_level
        
    def determine_risk_level(self, risk_factors):
        """Determine risk level based on factors found"""
        if not risk_factors:
            return "Low"
        
        high_risk_indicators = [
            "SSL certificate is invalid or expired",
            "Contains login form with username and password fields",
            "Legitimacy check failed:"
        ]
        
        medium_risk_indicators = [
            "Uses HTTP instead of HTTPS",
            "Uses multiple (",
            "Recently registered domain (",
            "Very similar to target domain"
        ]
        
        high_count = sum(1 for factor in risk_factors if any(indicator in factor for indicator in high_risk_indicators))
        medium_count = sum(1 for factor in risk_factors if any(indicator in factor for indicator in medium_risk_indicators))
        
        if high_count > 0:
            return "High"
        elif medium_count > 1 or (medium_count > 0 and len(risk_factors) > 2):
            return "Medium"
        else:
            return "Low"

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/analyze', methods=['POST'])
def analyze():
    target_domain = request.form.get('domain')
    if not target_domain:
        return jsonify({'success': False, 'error': 'Please enter a domain name'})
    
    if not target_domain.startswith(('http://', 'https://')):
        target_domain = 'https://' + target_domain
    
    parsed_domain = urlparse(target_domain)
    netloc = parsed_domain.netloc or parsed_domain.path
    
    analysis_id = str(uuid.uuid4())
    
    analysis_results[analysis_id] = {
        'target_domain': netloc,
        'status': 'processing',
        'progress': 0,
        'results': [],
        'start_time': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'end_time': None,
        'total_domains': 0,
        'processed_domains': 0
    }
    
    thread = threading.Thread(target=run_analysis, args=(netloc, analysis_id))
    thread.daemon = True
    thread.start()
    
    return jsonify({
        'success': True,
        'analysis_id': analysis_id,
        'redirect_url': f'/results/{analysis_id}'
    })

def run_analysis(target_domain, analysis_id):
    """Run the analysis and store results with progress updates"""
    detector = PhishingDetector(target_domain)
    
    analysis_results[analysis_id]['status'] = 'searching_domains'
    analysis_results[analysis_id]['progress'] = 20
    
    suspicious_domains = detector.get_suspicious_domains()
    
    if not suspicious_domains:
        analysis_results[analysis_id]['status'] = 'completed'
        analysis_results[analysis_id]['progress'] = 100
        analysis_results[analysis_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        return
    
    analysis_results[analysis_id]['status'] = 'analyzing_domains'
    analysis_results[analysis_id]['progress'] = 40
    analysis_results[analysis_id]['total_domains'] = len(suspicious_domains)
    analysis_results[analysis_id]['processed_domains'] = 0
    
    results = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        future_to_domain = {executor.submit(detector.analyze_domain, domain): domain for domain in suspicious_domains}
        
        for i, future in enumerate(concurrent.futures.as_completed(future_to_domain)):
            domain = future_to_domain[future]
            try:
                risk_factors, final_url, title, risk_level = future.result()
                
                if risk_factors:
                    results.append({
                        "domain": domain,
                        "url": final_url,
                        "title": title,
                        "risk_factors": risk_factors,
                        "risk_level": risk_level
                    })
                
                analysis_results[analysis_id]['processed_domains'] = i + 1
                analysis_results[analysis_id]['progress'] = 40 + (i / len(suspicious_domains)) * 60
                analysis_results[analysis_id]['results'] = results
                
            except Exception as e:
                print(f"Error analyzing {domain}: {e}")
    
    analysis_results[analysis_id]['status'] = 'completed'
    analysis_results[analysis_id]['progress'] = 100
    analysis_results[analysis_id]['results'] = results
    analysis_results[analysis_id]['end_time'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

@app.route('/results/<analysis_id>')
def results(analysis_id):
    if analysis_id not in analysis_results:
        return redirect(url_for('index'))
    
    return render_template('results.html', analysis_id=analysis_id)

@app.route('/api/analysis/<analysis_id>')
def get_analysis(analysis_id):
    if analysis_id not in analysis_results:
        return jsonify({'error': 'Analysis not found'}), 404
    
    return jsonify(analysis_results[analysis_id])

@app.route('/check-domain', methods=['POST'])
def check_domain():
    """Check a single domain for legitimacy"""
    data = request.get_json()
    domain = data.get('domain')
    target_domain = data.get('target_domain')
    
    if not domain or not target_domain:
        return jsonify({'error': 'Domain and target domain are required'}), 400
    
    checker = AdvancedDomainChecker(target_domain)
    is_legitimate, reason = checker.is_legitimate_domain(domain)
    
    return jsonify({
        'domain': domain,
        'is_legitimate': is_legitimate,
        'reason': reason
    })

def cross_validate_results(domain, gemini_result, ml_prediction, ml_probability):
    """Cross-validate Gemini and ML model results for consistency"""
    gemini_is_phishing = gemini_result.get('is_phishing', False)
    gemini_confidence = gemini_result.get('confidence', 0)
    
    ml_is_phishing = bool(ml_prediction == 1)
    ml_confidence = float(ml_probability[int(ml_prediction)]) * 100
    
    agreement = gemini_is_phishing == ml_is_phishing
    
    validation_result = {
        'agreement': agreement,
        'gemini_classification': 'Phishing' if gemini_is_phishing else 'Legitimate',
        'ml_classification': 'Phishing' if ml_is_phishing else 'Legitimate',
        'gemini_confidence': gemini_confidence,
        'ml_confidence': ml_confidence,
        'confidence_difference': abs(gemini_confidence - ml_confidence)
    }
    
    if agreement:
        validation_result['status'] = 'Both models agree'
        if abs(gemini_confidence - ml_confidence) < 20:
            validation_result['reliability'] = 'High'
        else:
            validation_result['reliability'] = 'Medium'
    else:
        validation_result['status'] = 'Models disagree - requires manual review'
        validation_result['reliability'] = 'Low'
        validation_result['warning'] = f"Gemini says {validation_result['gemini_classification']}, ML says {validation_result['ml_classification']}"
    
    print(f"Cross-validation for {domain}: {validation_result['status']} (Reliability: {validation_result['reliability']})")
    return validation_result

@app.route('/ml-detect', methods=['POST'])
def ml_detect():
    """Detect phishing domain using Gemini API with ML model fallback and cross-validation"""
    data = request.get_json()
    domain = data.get('domain')
    
    if not domain:
        return jsonify({'error': 'Domain is required'}), 400
    
    domain_clean = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    gemini_result, gemini_error = check_with_gemini(domain_clean)
    features = extract_ml_features(domain_clean)
    
    if gemini_result and ml_model:
        try:
            feature_columns = ['length', 'has_digit', 'has_hyphen', 'num_dots', 'num_digits', 'suspicious_keywords', 'tld_length', 'subdomain_count']
            feature_values = [features[col] for col in feature_columns]
            
            ml_prediction = ml_model.predict([feature_values])[0]
            ml_probability = ml_model.predict_proba([feature_values])[0]
            
            cross_validation = cross_validate_results(domain_clean, gemini_result, ml_prediction, ml_probability)
            
            result = {
                'domain': domain_clean,
                'is_phishing': gemini_result.get('is_phishing', False),
                'confidence': float(gemini_result.get('confidence', 0)),
                'classification': gemini_result.get('classification', 'Unknown'),
                'reasons': gemini_result.get('reasons', []),
                'detection_method': 'Google Gemini API (Cross-validated with ML)',
                'features': features,
                'cross_validation': cross_validation
            }
            return jsonify(result)
        except Exception as e:
            print(f"Cross-validation failed: {e}")
    
    if gemini_result:
        result = {
            'domain': domain_clean,
            'is_phishing': gemini_result.get('is_phishing', False),
            'confidence': float(gemini_result.get('confidence', 0)),
            'classification': gemini_result.get('classification', 'Unknown'),
            'reasons': gemini_result.get('reasons', []),
            'detection_method': 'Google Gemini API',
            'features': features
        }
        return jsonify(result)
    
    if ml_model is None:
        return jsonify({
            'error': 'Both Gemini API and ML model unavailable',
            'gemini_error': gemini_error
        }), 500
    
    try:
        features = extract_ml_features(domain_clean)
        feature_columns = ['length', 'has_digit', 'has_hyphen', 'num_dots', 'num_digits', 'suspicious_keywords', 'tld_length', 'subdomain_count']
        feature_values = [features[col] for col in feature_columns]
        
        prediction = ml_model.predict([feature_values])[0]
        probability = ml_model.predict_proba([feature_values])[0]
        
        is_phishing = bool(prediction == 1)
        confidence = float(probability[int(prediction)]) * 100
        
        result = {
            'domain': domain_clean,
            'is_phishing': is_phishing,
            'confidence': confidence,
            'classification': 'Phishing' if is_phishing else 'Legitimate',
            'detection_method': 'ML Model (Fallback)',
            'gemini_error': gemini_error,
            'features': features
        }
        
        return jsonify(result)
    
    except Exception as e:
        return jsonify({'error': f'Error processing domain: {str(e)}'}), 500

@app.route('/batch-detect', methods=['POST'])
def batch_detect():
    """Batch detect phishing domains using Gemini API with ML model fallback"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not file.filename.endswith(('.xlsx', '.xls')):
        return jsonify({'error': 'File must be Excel format (.xlsx or .xls)'}), 400
    
    try:
        df = pd.read_excel(file)
        
        if 'domain' not in df.columns:
            return jsonify({'error': 'Excel file must have a "domain" column'}), 400
        
        results = []
        gemini_count = 0
        ml_count = 0
        
        for domain in df['domain']:
            domain_clean = str(domain).replace('http://', '').replace('https://', '').split('/')[0]
            
            gemini_result, gemini_error = check_with_gemini(domain_clean)
            
            if gemini_result:
                results.append({
                    'domain': domain_clean,
                    'is_phishing': gemini_result.get('is_phishing', False),
                    'confidence': float(gemini_result.get('confidence', 0)),
                    'classification': gemini_result.get('classification', 'Unknown'),
                    'detection_method': 'Gemini API'
                })
                gemini_count += 1
            elif ml_model:
                features = extract_ml_features(domain_clean)
                feature_columns = ['length', 'has_digit', 'has_hyphen', 'num_dots', 'num_digits', 'suspicious_keywords', 'tld_length', 'subdomain_count']
                feature_values = [features[col] for col in feature_columns]
                
                prediction = ml_model.predict([feature_values])[0]
                probability = ml_model.predict_proba([feature_values])[0]
                
                is_phishing = bool(prediction == 1)
                confidence = float(probability[int(prediction)]) * 100
                
                results.append({
                    'domain': domain_clean,
                    'is_phishing': is_phishing,
                    'confidence': confidence,
                    'classification': 'Phishing' if is_phishing else 'Legitimate',
                    'detection_method': 'ML Model'
                })
                ml_count += 1
            else:
                results.append({
                    'domain': domain_clean,
                    'error': 'Both Gemini API and ML model unavailable'
                })
        
        return jsonify({
            'results': results, 
            'total': len(results),
            'gemini_count': gemini_count,
            'ml_count': ml_count
        })
    
    except Exception as e:
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)
