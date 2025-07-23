# backend/analysis/phishing.py

# This file will contain the core logic for phishing detection.
# It will include:
# - Functions to check URLs against blacklists (PhishTank, Google Safe Browsing, etc.).
# - Heuristic analysis functions (e.g., suspicious URL patterns, keywords, domain structures).
# - A function to assign a risk score and determine threat level.

import re
import requests
import json
from urllib.parse import urlparse
import idna # For punycode detection

# --- Configuration for API Keys (managed by set_api_keys function) ---
_PHISHTANK_API_KEY = None
_GOOGLE_SAFE_BROWSING_API_KEY = None
_VIRUSTOTAL_API_KEY = None # Optional, not currently used in the main analysis flow

def set_api_keys(phishtank_key, gsb_key, virustotal_key=None):
    """Sets the API keys dynamically from the application settings."""
    global _PHISHTANK_API_KEY, _GOOGLE_SAFE_BROWSING_API_KEY, _VIRUSTOTAL_API_KEY
    _PHISHTANK_API_KEY = phishtank_key
    _GOOGLE_SAFE_BROWSING_API_KEY = gsb_key
    _VIRUSTOTAL_API_KEY = virustotal_key
    print("Phishing module: API keys updated.")

# --- Blacklist Check Functions ---

def check_phishtank(url):
    """
    Checks a URL against the PhishTank database.
    Returns (True if phishing, "Reason") or (False, "Reason").
    Requires a PhishTank API key.
    """
    if not _PHISHTANK_API_KEY:
        # print("PhishTank API key not configured. Skipping check.") # Suppress for production
        return False, "API_KEY_MISSING"

    api_url = "http://checkurl.phishtank.com/checkurl/"
    headers = {'User-Agent': 'PhishTank/1.0'}
    data = {
        'url': url,
        'format': 'json',
        'api_key': _PHISHTANK_API_KEY
    }

    try:
        response = requests.post(api_url, data=data, headers=headers, timeout=5)
        response.raise_for_status() # Raise an HTTPError for bad responses (4xx or 5xx)
        result = response.json()

        if result and 'results' in result and result['results']['in_database']:
            if result['results']['verified']:
                return True, "PhishTank_Verified"
            else:
                return True, "PhishTank_Unverified" # Still in database, but not yet verified
        return False, "Not_Phishing"
    except requests.exceptions.RequestException as e:
        print(f"Error checking PhishTank for {url}: {e}")
        return False, f"PhishTank_Error: {e}"
    except json.JSONDecodeError:
        print(f"PhishTank returned invalid JSON for {url}")
        return False, "PhishTank_Invalid_Response"


def check_google_safe_browsing(url):
    """
    Checks a URL against Google Safe Browsing API.
    Returns (True if threat, "Reason") or (False, "Reason").
    Requires a Google Safe Browsing API key.
    """
    if not _GOOGLE_SAFE_BROWSING_API_KEY:
        # print("Google Safe Browsing API key not configured. Skipping check.") # Suppress for production
        return False, "API_KEY_MISSING"

    api_url = f"https://safebrowsing.googleapis.com/v4/threatMatches:find?key={_GOOGLE_SAFE_BROWSING_API_KEY}"
    payload = {
        "client": {
            "clientId": "NetScan", # Your application name
            "clientVersion": "1.0.0"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["ANY_PLATFORM"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [{"url": url}]
        }
    }

    try:
        response = requests.post(api_url, json=payload, timeout=5)
        response.raise_for_status()
        result = response.json()
        if 'matches' in result and result['matches']:
            # Extract threat type from the first match
            threat_type = result['matches'][0]['threatType'] if result['matches'] else "Unknown"
            return True, f"GoogleSafeBrowsing_{threat_type}"
        return False, "Not_Threat"
    except requests.exceptions.RequestException as e:
        print(f"Error checking Google Safe Browsing for {url}: {e}")
        return False, f"GSB_Error: {e}"
    except json.JSONDecodeError:
        print(f"Google Safe Browsing returned invalid JSON for {url}")
        return False, "GSB_Invalid_Response"

# --- Heuristic Analysis Functions ---

def is_ip_based_url(url):
    """Checks if the URL uses an IP address instead of a domain name."""
    try:
        parsed_url = urlparse(url)
        # Basic check for IPv4. For IPv6, it's more complex.
        if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(:\d+)?$", parsed_url.netloc):
            return True
        # Also check if it's an IPv6 address (simple check for brackets)
        if parsed_url.netloc.startswith('[') and parsed_url.netloc.endswith(']'):
            return True
    except Exception as e:
        print(f"Error parsing URL for IP-based check {url}: {e}")
    return False

def has_suspicious_keywords(url):
    """Checks for suspicious keywords in the URL path or query."""
    suspicious_keywords = [
        'login', 'signin', 'verify', 'account', 'bank', 'secure', 'update',
        'password', 'webscr', 'confirm', 'authorize', 'billing', 'support',
        'activity', 'suspicious', 'alert', 'urgent', 'payment', 'transfer'
    ]
    try:
        parsed_url = urlparse(url)
        # Check in hostname, path, and query
        full_string = (parsed_url.hostname or '') + (parsed_url.path or '') + (parsed_url.query or '')
        full_string = full_string.lower()
        return any(keyword in full_string for keyword in suspicious_keywords)
    except Exception as e:
        print(f"Error parsing URL for suspicious keywords {url}: {e}")
    return False

def has_punycode(url):
    """Checks if the URL contains punycode (IDN homograph attack)."""
    try:
        domain = urlparse(url).netloc
        if domain.startswith("xn--"):
            try:
                # Attempt to decode punycode. If it decodes successfully, it's punycode.
                idna.decode(domain)
                return True
            except idna.IDNAError:
                # Malformed punycode, still suspicious
                return True
    except Exception as e:
        print(f"Error checking punycode for {url}: {e}")
    return False

def has_abnormal_domain_structure(url):
    """
    Checks for suspicious domain patterns like:
    - Domain in subdomain (e.g., paypal.com.malicious.com)
    - Too many subdomains
    - Long domain names
    """
    try:
        parsed_url = urlparse(url)
        hostname = parsed_url.hostname
        if not hostname:
            return False, "No_Hostname"

        domain_parts = hostname.split('.')
        num_parts = len(domain_parts)

        # 1. Check for domain in subdomain (e.g., paypal.com.login.malicious.com)
        common_tlds = ['.com', '.org', '.net', '.info', '.biz', '.co', '.us', '.io']
        for i in range(num_parts - 2): # Iterate up to the part before SLD.TLD
            if '.' + domain_parts[i].lower() in common_tlds:
                return True, "Domain_in_Subdomain"

        # 2. Too many subdomains (excluding www)
        effective_subdomains = [p for p in domain_parts[:-2] if p.lower() != 'www']
        if len(effective_subdomains) > 3: # Example threshold
            return True, "Too_Many_Subdomains"

        # 3. Very long domain names (might indicate obfuscation)
        if len(hostname) > 50: # Arbitrary length threshold
             return True, "Excessive_Length"

    except Exception as e:
        print(f"Error checking abnormal domain structure for {url}: {e}")
    return False, "Normal_Structure"

# --- Main Phishing Detection Function ---

def analyze_url_for_phishing(url):
    """
    Analyzes a given URL for phishing indicators using blacklists and heuristics.
    Returns a dictionary with risk score, threat level, and detection methods.
    """
    risk_score = 0
    detection_methods = []
    threat_level = "Low"

    if not url or not url.strip().startswith(('http://', 'https://')):
        # If URL is empty or not a valid HTTP/S URL, return minimal info
        return {
            "url": url,
            "risk_score": 0,
            "threat_level": "None",
            "detection_methods": ["Invalid or non-HTTP/S URL"]
        }

    # Normalize URL (e.g., remove fragments, sort query params if needed)
    try:
        parsed_url = urlparse(url)
        clean_url = parsed_url.geturl() # Get the reconstructed URL
    except Exception:
        clean_url = url # Fallback if parsing fails

    # 1. Blacklist Checks (High Impact)
    is_phishtank_phishing, phishtank_reason = check_phishtank(clean_url)
    if is_phishtank_phishing:
        risk_score += 50
        detection_methods.append(f"Blacklist: PhishTank ({phishtank_reason})")

    is_gsb_threat, gsb_reason = check_google_safe_browsing(clean_url)
    if is_gsb_threat:
        risk_score += 40
        detection_methods.append(f"Blacklist: Google Safe Browsing ({gsb_reason})")

    # 2. Heuristic Analysis (Varying Impact)
    if is_ip_based_url(clean_url):
        risk_score += 30
        detection_methods.append("Heuristic: IP-based URL")

    if has_suspicious_keywords(clean_url):
        risk_score += 25
        detection_methods.append("Heuristic: Suspicious Keywords")

    if has_punycode(clean_url):
        risk_score += 35
        detection_methods.append("Heuristic: Punycode Detected")

    abnormal_domain, abnormal_reason = has_abnormal_domain_structure(clean_url)
    if abnormal_domain:
        risk_score += 20
        detection_methods.append(f"Heuristic: Abnormal Domain ({abnormal_reason})")

    # Determine overall threat level based on accumulated risk score
    if risk_score >= 80:
        threat_level = "High"
    elif risk_score >= 40:
        threat_level = "Medium"
    elif risk_score > 0:
        threat_level = "Low"
    else:
        threat_level = "None" # No indicators found

    return {
        "url": url, # Original URL
        "risk_score": risk_score,
        "threat_level": threat_level,
        "detection_methods": detection_methods if detection_methods else ["No suspicious indicators"]
    }

# Example usage (for testing this module independently)
if __name__ == "__main__":
    # For independent testing, set dummy API keys
    set_api_keys("YOUR_PHISHTANK_API_KEY", "YOUR_GOOGLE_SAFE_BROWSING_API_KEY")

    test_urls = [
        "https://www.google.com",
        "http://192.168.1.1/login.php", # IP-based, suspicious keyword
        "http://example.com/secure/login?user=test", # Suspicious keyword
        "http://xn--paypal-kt0a.com/", # Punycode
        "http://paypal.com.login.malicious.com/verify", # Abnormal subdomain, suspicious keyword
        "http://malicious.link/phish",
        "https://docs.python.org/3/",
        "http://www.evil-site.com/bank/login.html",
        "https://www.amazon.com",
        "http://www.microsoft.com.update.bad.com/patch",
        "http://[::1]/admin" # IPv6 example
    ]

    print("--- Phishing Analysis Test ---")
    for url in test_urls:
        result = analyze_url_for_phishing(url)
        print(f"\nURL: {result['url']}")
        print(f"  Risk Score: {result['risk_score']}")
        print(f"  Threat Level: {result['threat_level']}")
        print(f"  Detection Methods: {', '.join(result['detection_methods'])}")
