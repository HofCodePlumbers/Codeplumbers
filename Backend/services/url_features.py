import re
import requests
import socket
import whois
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime
import ipaddress

FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortening_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "Web_Traffic", "Page_Rank", "Google_Index",
    "Links_pointing_to_page", "Statistical_report"
]

# Blocklist for potentially malicious domains
DOMAIN_BLOCKLIST = [
    'example-malicious-domain.com',
    'evil-domain.com',
    # Add more as needed
]

# Maximum number of external requests allowed per function call
MAX_EXTERNAL_REQUESTS = 5

def is_url_safe(url):
    """
    Validate if a URL is safe to process.
    Returns (is_safe, reason) tuple.
    """
    # Check if URL is valid
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"
        
    # Basic URL format validation (must start with http:// or https://)
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    # Parse the URL
    try:
        parsed = urlparse(url)
        if not parsed.netloc:
            return False, "URL must have a valid domain"
            
        # Get domain info
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        # Check for IP-based URLs - allow but note them as potentially risky
        if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", parsed.netloc):
            pass
            
        # Check domain against blocklist
        if domain in DOMAIN_BLOCKLIST:
            return False, f"Domain {domain} is in blocklist"
            
        # Check for overly complex URLs (potential obfuscation)
        if url.count('?') > 3 or url.count('&') > 10:
            return False, "URL has too many query parameters"
            
        # Detect URL encoding attacks
        if '%25' in url.lower() or '%00' in url.lower():
            return False, "URL contains suspicious encoded characters"
            
        return True, "URL is safe"
        
    except Exception as e:
        return False, f"URL validation error: {str(e)}"

def safe_request_get(url, **kwargs):
    """
    Makes a safe HTTP GET request after validating the URL.
    
    Args:
        url (str): The URL to request
        **kwargs: Additional arguments to pass to requests.get
        
    Returns:
        Response or None: The response if successful and URL was safe, None otherwise
    """
    if not is_url_safe(url)[0]:
        return None
    
    try:
        return requests.get(url, **kwargs)
    except Exception:
        return None

def extract_features_from_url(url):
    """
    Extract features from a URL for ML classification.
    The URL is first validated for basic safety.
    """
    # Validate URL before processing
    is_safe, reason = is_url_safe(url)
    if not is_safe:
        # Instead of rejecting completely, we'll set default values that indicate high risk
        features = [1] * len(FEATURE_NAMES)  # Default to high-risk indicators
        return features
    
    features = []
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    
    # Extract domain info
    domain_info = tldextract.extract(url)
    full_domain = f"{domain_info.domain}.{domain_info.suffix}"
    
    # Track the number of external requests to prevent DoS
    external_request_count = 0
    
    # Request page content with better error handling and timeouts
    html = ""
    soup = None
    response = None
    
    if external_request_count < MAX_EXTERNAL_REQUESTS:
        try:
            response = safe_request_get(url, timeout=3, allow_redirects=True, 
                                   headers={"User-Agent": "Mozilla/5.0"})
            external_request_count += 1
            if response:
                html = response.text
                soup = BeautifulSoup(html, 'html.parser')
        except:
            # Fail silently but log the error in a production system
            pass
    
    # WHOIS data with better error handling
    whois_data = None
    if external_request_count < MAX_EXTERNAL_REQUESTS:
        try:
            whois_data = whois.whois(full_domain)
            external_request_count += 1
        except:
            # Fail silently
            pass

    # 1. IP in URL
    features.append(1 if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain) else -1)

    # 2. URL Length
    features.append(1 if len(url) >= 75 else 0 if len(url) >= 54 else -1)

    # 3. Shortening service
    features.append(1 if re.search(r"(bit\.ly|goo\.gl|tinyurl|ow\.ly|t\.co)", url) else -1)

    # 4. '@' symbol
    features.append(1 if "@" in url else -1)

    # 5. Double slash redirect
    features.append(1 if url.rfind('//') > 6 else -1)

    # 6. Prefix/Suffix (hyphen)
    features.append(1 if '-' in domain else -1)

    # 7. Subdomain
    subdomain_count = domain.count('.')
    features.append(1 if subdomain_count > 2 else 0 if subdomain_count == 2 else -1)

    # 8. SSL final state (https)
    features.append(1 if parsed.scheme == 'https' else -1)

    # 9. Domain registration length
    try:
        if whois_data and whois_data.expiration_date and whois_data.updated_date:
            exp = whois_data.expiration_date
            upd = whois_data.updated_date
            if isinstance(exp, list): exp = exp[0]
            if isinstance(upd, list): upd = upd[0]
            duration = (exp - upd).days
            features.append(1 if duration > 365 else -1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    # 10. Favicon external
    try:
        icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower()) if soup else None
        if icon and icon.get('href'):
            features.append(-1 if domain not in icon['href'] else 1)
        else:
            features.append(1)
    except:
        features.append(-1)

    # 11. Port
    features.append(1 if ':' in domain else -1)

    # 12. HTTPS token in domain
    features.append(1 if 'https' in domain.lower() else -1)

    # 13. Request URL external content (e.g., images/scripts)
    try:
        if soup:
            total = 0
            external = 0
            for tag in soup.find_all(['img', 'script'], src=True):
                total += 1
                if domain not in tag['src']:
                    external += 1
            ratio = external / total if total else 0
            features.append(1 if ratio > 0.61 else 0 if 0.22 < ratio <= 0.61 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 14. Anchor tags pointing elsewhere
    try:
        if soup:
            anchors = soup.find_all('a', href=True)
            total = len(anchors)
            unsafe = sum(1 for a in anchors if "#" in a['href'] or "javascript" in a['href'].lower())
            ratio = unsafe / total if total else 0
            features.append(1 if ratio > 0.67 else 0 if 0.31 < ratio <= 0.67 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 15. Meta/script/link tags external
    try:
        if soup:
            tags = soup.find_all(['meta', 'script', 'link'])
            total = len(tags)
            unsafe = sum(1 for tag in tags if domain not in str(tag))
            ratio = unsafe / total if total else 0
            features.append(1 if ratio > 0.81 else 0 if 0.17 < ratio <= 0.81 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 16. SFH (server form handler)
    try:
        if soup:
            forms = soup.find_all('form')
            for f in forms:
                if f.get('action') in ["", "about:blank"]:
                    features.append(1)
                    break
                elif domain not in f.get('action', ''):
                    features.append(0)
                    break
            else:
                features.append(-1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 17. Submitting to email
    features.append(1 if html and "mailto:" in html else -1)

    # 18. Abnormal URL
    features.append(1 if domain not in url else -1)

    # 19. Redirect count - reuse response instead of making a new request
    try:
        if response:
            features.append(1 if len(response.history) > 3 else 0 if len(response.history) else -1)
        else:
            features.append(1)  # Default to suspicious if no response
    except:
        features.append(-1)

    # 20. onmouseover
    features.append(1 if html and "onmouseover" in html else -1)

    # 21. Right click disabled
    features.append(1 if html and "event.button==2" in html else -1)

    # 22. Popup
    features.append(1 if html and "window.open" in html else -1)

    # 23. iframe
    features.append(1 if soup and soup.find("iframe") else -1)

    # 24. Age of domain
    try:
        if whois_data and whois_data.creation_date:
            created = whois_data.creation_date
            if isinstance(created, list): created = created[0]
            age_days = (datetime.now() - created).days
            features.append(1 if age_days > 365 else -1)
        else:
            features.append(-1)
    except:
        features.append(-1)

    # 25. DNS record - limit requests
    if external_request_count < MAX_EXTERNAL_REQUESTS:
        try:
            socket.gethostbyname(domain)
            external_request_count += 1
            features.append(-1)
        except:
            features.append(1)
    else:
        features.append(1)  # Default to suspicious if max requests reached

    # 26. Web Traffic - limit external request, reuse existing when possible
    if external_request_count < MAX_EXTERNAL_REQUESTS:
        try:
            traffic_url = f"https://www.{full_domain}"
            if is_url_safe(traffic_url)[0]:
                traffic = safe_request_get(traffic_url, timeout=3)
                external_request_count += 1
                features.append(1 if traffic and traffic.status_code == 200 else -1)
            else:
                features.append(1)  # Default to suspicious if URL is not safe
        except:
            features.append(-1)
    else:
        features.append(1)  # Default to suspicious

    # 27. Page Rank (simulate with number of anchor tags with hrefs)
    try:
        if soup:
            anchors = soup.find_all('a', href=True)
            features.append(1 if len(anchors) > 50 else 0 if 10 < len(anchors) <= 50 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 28. Google Index - skip this request entirely since it's risky and unreliable
    features.append(0)  # Neutral score instead of making external request

    # 29. Links pointing to page (simulate by counting backlinks in soup)
    try:
        if soup:
            backlinks = [a for a in soup.find_all('a', href=True) if full_domain in a['href']]
            features.append(1 if len(backlinks) > 5 else 0 if len(backlinks) > 1 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 30. Statistical report - avoid making additional requests
    try:
        blacklist = ['malwaredomainlist.com', 'phishtank.org', 'stopbadware.org', 'clean-mx.com', 'malc0de.com']
        features.append(1 if any(b in url for b in blacklist) else -1)
    except:
        features.append(-1)

    return features