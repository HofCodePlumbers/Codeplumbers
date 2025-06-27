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

# Define missing constants
DOMAIN_BLOCKLIST = set()  # Fill with known bad domains if needed
MAX_EXTERNAL_REQUESTS = 3

def is_url_safe(url):
    """
    Validates if a URL is safe to make requests to.
    Checks for proper URL format, allowed schemes, and non-private IPs.
    Returns:
        bool: True if URL is considered safe, False otherwise
    """
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ['http', 'https']:
            return False
        if not parsed.netloc:
            return False
        domain = parsed.netloc.split(':')[0]
        if domain in ['localhost', '127.0.0.1', '::1'] or domain.startswith('127.'):
            return False
        try:
            ip = ipaddress.ip_address(domain)
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved:
                return False
        except ValueError:
            pass
        return True
    except Exception:
        return False

def safe_request_get(url, **kwargs):
    """
    Makes a safe HTTP GET request after validating the URL.
    Returns:
        Response or None: The response if successful and URL was safe, None otherwise
    """
    if not is_url_safe(url):
        return None
    try:
        return requests.get(url, **kwargs)
    except Exception:
        return None

def extract_features_from_url(url):
    """
    Extract features from a URL for ML classification.
    The URL is first validated for basic safety.
    Returns a list of features (length matches FEATURE_NAMES).
    """
    # Validate URL before processing
    if not url or not isinstance(url, str):
        return [1] * len(FEATURE_NAMES)  # Default to high-risk indicators

    if not url.startswith(('http://', 'https://')):
        return [1] * len(FEATURE_NAMES)

    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    domain_info = tldextract.extract(url)
    full_domain = f"{domain_info.domain}.{domain_info.suffix}"

    # Blocklist check
    if full_domain in DOMAIN_BLOCKLIST:
        return [1] * len(FEATURE_NAMES)

    features = []
    external_request_count = 0
    html = ""
    soup = None
    response = None

    # Try to get page content
    if external_request_count < MAX_EXTERNAL_REQUESTS:
        try:
            response = safe_request_get(url, timeout=5, headers={"User-Agent": "Mozilla/5.0"})
            external_request_count += 1
            if response:
                html = response.text
                soup = BeautifulSoup(html, 'html.parser')
        except Exception:
            pass

    # WHOIS data
    whois_data = None
    if external_request_count < MAX_EXTERNAL_REQUESTS:
        try:
            whois_data = whois.whois(full_domain)
            external_request_count += 1
        except Exception:
            pass

    # 1. IP in URL
    features.append(1 if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain) else -1)

    # 2. URL Length
    features.append(1 if len(url) >= 75 else 0 if len(url) >= 54 else -1)

    # 3. Shortening Service (example: bit.ly, tinyurl, etc.)
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl', 'ow.ly', 't.co', 'bit.do', 'shorte.st', 'adf.ly']
    features.append(1 if any(s in domain for s in shortening_services) else -1)

    # 4. Having '@' symbol
    features.append(1 if '@' in url else -1)

    # 5. Double slash redirecting
    features.append(1 if url.count('//') > 1 else -1)

    # 6. Prefix/Suffix in domain
    features.append(1 if '-' in domain else -1)

    # 7. Having subdomain
    subdomain_count = domain_info.subdomain.count('.') + 1 if domain_info.subdomain else 0
    features.append(1 if subdomain_count >= 2 else 0 if subdomain_count == 1 else -1)

    # 8. SSLfinal_State (very basic: https or not)
    features.append(1 if parsed.scheme == 'https' else -1)

    # 9. Domain registration length (from WHOIS)
    try:
        exp = whois_data.expiration_date
        upd = whois_data.updated_date
        if isinstance(exp, list): exp = exp[0]
        if isinstance(upd, list): upd = upd[0]
        duration = (exp - upd).days if exp and upd else 0
        features.append(1 if duration > 365 else -1)
    except Exception:
        features.append(-1)

    # 10. Favicon external
    try:
        icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower()) if soup else None
        if icon and icon.get('href'):
            features.append(-1 if domain not in icon['href'] else 1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 11. Port (non-standard)
    features.append(1 if ':' in parsed.netloc and not parsed.netloc.endswith(':80') and not parsed.netloc.endswith(':443') else -1)

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
            features.append(1 if ratio > 0.81 else 0 if 0.17 < ratio <= 0.81 else -1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 14. URL of Anchor
    try:
        if soup:
            anchors = soup.find_all('a', href=True)
            unsafe = sum(1 for a in anchors if domain not in a['href'])
            ratio = unsafe / len(anchors) if anchors else 0
            features.append(1 if ratio > 0.67 else 0 if 0.31 < ratio <= 0.67 else -1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 15. Links in tags (meta/script/link)
    try:
        if soup:
            tags = soup.find_all(['meta', 'script', 'link'], href=True)
            unsafe = sum(1 for tag in tags if domain not in tag['href'])
            ratio = unsafe / len(tags) if tags else 0
            features.append(1 if ratio > 0.81 else 0 if 0.17 < ratio <= 0.81 else -1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 16. SFH (server form handler)
    try:
        if soup:
            forms = soup.find_all('form', action=True)
            if not forms:
                features.append(1)
            else:
                for f in forms:
                    if f.get('action') == "" or f.get('action') == "about:blank":
                        features.append(1)
                        break
                    elif domain not in f.get('action', ''):
                        features.append(0)
                        break
                else:
                    features.append(-1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 17. Submitting to email
    features.append(1 if html and "mailto:" in html else -1)

    # 18. Abnormal URL
    features.append(1 if domain not in url else -1)

    # 19. Redirect count
    try:
        if response:
            features.append(1 if len(response.history) > 3 else 0 if len(response.history) else -1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 20. onmouseover
    features.append(1 if html and "onmouseover" in html else -1)

    # 21. Right click disabled
    features.append(1 if html and "event.button==2" in html else -1)

    # 22. Popup
    features.append(1 if html and "window.open" in html else -1)

    # 23. iframe
    features.append(1 if soup and soup.find("iframe") else -1)

    # 24. Age of domain (from WHOIS)
    try:
        creation = whois_data.creation_date
        if isinstance(creation, list): creation = creation[0]
        age = (datetime.now() - creation).days if creation else 0
        features.append(1 if age >= 180 else -1)
    except Exception:
        features.append(-1)

    # 25. DNS record
    try:
        socket.gethostbyname(domain)
        features.append(-1)
    except Exception:
        features.append(1)

    # 26. Web Traffic (simulate with reachability check)
    try:
        traffic_url = f"https://www.{full_domain}"
        traffic = safe_request_get(traffic_url, timeout=5)
        features.append(1 if traffic and traffic.status_code == 200 else -1)
    except Exception:
        features.append(-1)

    # 27. Page Rank (simulate with number of anchor tags with hrefs)
    try:
        if soup:
            anchors = soup.find_all('a', href=True)
            features.append(1 if len(anchors) > 50 else 0 if 10 < len(anchors) <= 50 else -1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 28. Google Index (skip actual request, neutral score)
    features.append(0)

    # 29. Links pointing to page (simulate by counting backlinks in soup)
    try:
        if soup:
            backlinks = [a for a in soup.find_all('a', href=True) if full_domain in a['href']]
            features.append(1 if len(backlinks) > 5 else 0 if len(backlinks) > 1 else -1)
        else:
            features.append(1)
    except Exception:
        features.append(-1)

    # 30. Statistical report (real domain/URL check against blacklist)
    try:
        blacklist = ['malwaredomainlist.com', 'phishtank.org', 'stopbadware.org', 'clean-mx.com', 'malc0de.com']
        features.append(1 if any(b in url for b in blacklist) else -1)
    except Exception:
        features.append(-1)

    # Ensure the feature vector is the correct length
    while len(features) < len(FEATURE_NAMES):
        features.append(-1)

    return features