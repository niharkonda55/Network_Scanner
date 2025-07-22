import re

def is_blacklisted(url):
    # Placeholder for real blacklist API check (PhishTank, Google Safe Browsing, etc.)
    # Return True if blacklisted, False otherwise
    # In production, call the real API here
    return False

def heuristic_score(url):
    score = 0
    # Heuristic 1: IP-based URL
    if re.match(r'https?://\d+\.\d+\.\d+\.\d+', url):
        score += 3
    # Heuristic 2: Punycode
    if 'xn--' in url:
        score += 2
    # Heuristic 3: Suspicious keywords
    if re.search(r'(login|verify|account|secure|update|bank|password)', url, re.I):
        score += 2
    # Heuristic 4: Abnormal domain structure
    if re.search(r'-login|-secure|-account', url):
        score += 1
    # Heuristic 5: Long or complex domain
    if len(url) > 60:
        score += 1
    return score

def risk_level(score, blacklisted):
    if blacklisted:
        return 'High', 10
    if score >= 5:
        return 'High', score
    elif score >= 3:
        return 'Medium', score
    elif score >= 1:
        return 'Low', score
    else:
        return 'None', score

def analyze_url(url):
    blacklisted = is_blacklisted(url)
    score = heuristic_score(url)
    level, final_score = risk_level(score, blacklisted)
    return {
        'url': url,
        'blacklisted': blacklisted,
        'score': final_score,
        'level': level
    } 