import re
import requests
import socket
import whois
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse, unquote
from datetime import datetime
import ipaddress

# Constants
FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortening_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "Web_Traffic", "Page_Rank", "Google_Index",
    "Links_pointing_to_page", "Statistical_report"
]

# Maximum number of external requests to make to prevent DoS
MAX_EXTERNAL_REQUESTS = 3

# Blocklist for known malicious or high-risk domains
DOMAIN_BLOCKLIST = [
    'malwaredomainlist.com', 'phishtank.org', 'stopbadware.org', 
    'clean-mx.com', 'malc0de.com'
]

# Known URL shortening services
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'cli.gs', 'pic.gd', 'su.pr', 'twurl.nl', 'snipurl.com',
    'short.to', 'budurl.com', 'ping.fm', 'post.ly', 'just.as',
    'bkite.com', 'snipr.com', 'fic.kr', 'loopt.us', 'doiop.com',
    'twitthis.com', 'htxt.it', 'ak.im', 'hex.io', 'cutt.ly', 'tr.im'
]

def is_private_ip(ip_str):
    """
    Check if the provided IP string represents a private/internal IP address.
    
    Args:
        ip_str (str): IP address to check
        
    Returns:
        bool: True if IP is private/internal, False otherwise
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        return (
            ip.is_private or 
            ip.is_loopback or 
            ip.is_link_local or 
            ip.is_multicast or 
            ip.is_reserved or 
            ip.is_unspecified
        )
    except ValueError:
        return False

def contains_ip_or_localhost(text):
    """
    Check if the text contains any localhost or IP address references.
    
    Args:
        text (str): Text to check for localhost/IP references
        
    Returns:
        bool: True if contains localhost or IP references, False otherwise
    """
    # Check for common localhost names and their encoded forms
    localhost_patterns = [
        r'localhost',
        r'127\.0\.0\.1',
        r'0\.0\.0\.0',
        r'::1',
        # Decimal/octal/hex notation for localhost
        r'2130706433',  # Decimal for 127.0.0.1
        r'017700000001', # Octal for 127.0.0.1
        r'0x7f000001'   # Hex for 127.0.0.1
    ]
    
    for pattern in localhost_patterns:
        if re.search(pattern, text, re.IGNORECASE):
            return True
    
    # Check for IP addresses in the text
    ip_pattern = r'(\d{1,3}\.){3}\d{1,3}'
    ip_matches = re.finditer(ip_pattern, text)
    for match in ip_matches:
        # Extract the full IP from the match
        ip_addr = text[match.start():match.end()]
        if is_private_ip(ip_addr):
            return True
    
    return False

def is_url_safe(url):
    """
    Enhanced URL validation with more thorough safety checks.
    
    Returns:
        tuple: (bool, str) - Whether URL is safe and reason if not
    """
    if not url or not isinstance(url, str):
        return False, "URL must be a non-empty string"
        
    # Basic URL format validation (must start with http:// or https://)
    if not url.startswith(('http://', 'https://')):
        return False, "URL must start with http:// or https://"
    
    try:
        # Decode URL to handle URL encoding bypass attempts
        decoded_url = unquote(url)
        # Check for multiple levels of encoding
        while '%' in decoded_url:
            next_level = unquote(decoded_url)
            if next_level == decoded_url:  # No further decoding possible
                break
            decoded_url = next_level
        
        # Parse the URL
        parsed = urlparse(decoded_url)
        
        # Check scheme (only http and https allowed)
        if parsed.scheme not in ['http', 'https']:
            return False, "URL scheme must be http or https"
        
        # Check if domain is valid
        if not parsed.netloc:
            return False, "URL must have a valid domain"
        
        # Extract domain and port
        netloc_parts = parsed.netloc.split(':')
        domain = netloc_parts[0]
        
        # Check port if specified
        if len(netloc_parts) > 1:
            try:
                port = int(netloc_parts[1])
                # Block requests to non-standard ports
                if port not in {80, 443}:
                    return False, "URL contains a non-standard port"
            except ValueError:
                return False, "URL contains an invalid port"
        
        # Check for localhost references in any part of the URL
        if contains_ip_or_localhost(decoded_url):
            return False, "URL contains localhost or internal IP references"
        
        # Check for direct IP address in domain
        try:
            ip = ipaddress.ip_address(domain)
            if is_private_ip(str(ip)):
                return False, "URL contains a private IP address"
        except ValueError:
            # Not an IP address, continue with domain validation
            pass
        
        # DNS resolution check to prevent DNS rebinding attacks
        try:
            # Resolve domain to IP
            ip_addresses = socket.getaddrinfo(domain, None)
            for addr_info in ip_addresses:
                ip_str = addr_info[4][0]  # Extract the IP from address info
                if is_private_ip(ip_str):
                    return False, "Domain resolves to a private IP address"
        except socket.gaierror:
            # If DNS resolution fails, it might be a non-existent domain
            pass
        
        # Get domain info
        domain_info = tldextract.extract(url)
        domain = f"{domain_info.domain}.{domain_info.suffix}"
        
        # Check domain against blocklist
        if domain in DOMAIN_BLOCKLIST:
            return False, f"Domain {domain} is in blocklist"
            
        # Check for overly complex URLs (potential obfuscation)
        if url.count('?') > 3 or url.count('&') > 10:
            return False, "URL has too many query parameters"
            
        # Detect URL encoding attacks
        if '%25' in url.lower() or '%00' in url.lower():
            return False, "URL contains suspicious encoded characters"
            
        # Check for excessive subdomains (potential for confusion/phishing)
        if domain_info.subdomain.count('.') > 3:
            return False, "URL has too many subdomains"
            
        # Check for unusually long hostnames
        if len(parsed.netloc) > 100:
            return False, "Hostname is suspiciously long"
            
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
    is_safe, reason = is_url_safe(url)
    if not is_safe:
        return None
    
    # Ensure sensible defaults for timeout and redirects
    if 'timeout' not in kwargs:
        kwargs['timeout'] = 5
    if 'allow_redirects' not in kwargs:
        # Limit redirects to prevent redirect chains and open redirect attacks
        kwargs['allow_redirects'] = True
        if 'max_redirects' not in kwargs:
            kwargs['max_redirects'] = 3
            
    # Add User-Agent if not provided
    if 'headers' not in kwargs:
        kwargs['headers'] = {"User-Agent": "Mozilla/5.0"}
    elif 'User-Agent' not in kwargs['headers']:
        kwargs['headers']["User-Agent"] = "Mozilla/5.0"
    
    try:
        return requests.get(url, **kwargs)
    except Exception:
        return None

def extract_features_from_url(url):
    """
    Extract features from a URL for ML classification with enhanced security.
    The URL is first validated for basic safety, and all external requests are 
    carefully managed to prevent attacks.
    
    Args:
        url (str): The URL to extract features from
        
    Returns:
        list: A list of feature values or None if URL processing failed
    """
    # Validate URL before processing
    is_safe, reason = is_url_safe(url)
    if not is_safe:
        # Set default values that indicate high risk when URL validation fails
        return [1] * len(FEATURE_NAMES)  # Default to high-risk indicators
    
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
            response = safe_request_get(url, timeout=3, allow_redirects=True)
            if response:
                external_request_count += 1
                html = response.text
                soup = BeautifulSoup(html, 'html.parser')
        except:
            # Fail silently but in production would log the error
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

    # 1. IP in URL - look for IP address in domain
    features.append(1 if re.match(r"^\d{1,3}(?:\.\d{1,3}){3}$", domain) else -1)

    # 2. URL Length - longer URLs are more suspicious
    features.append(1 if len(url) >= 75 else 0 if len(url) >= 54 else -1)

    # 3. Shortening Service
    features.append(1 if any(shortener in domain for shortener in URL_SHORTENERS) else -1)

    # 4. Having @ Symbol
    features.append(1 if '@' in url else -1)

    # 5. Double Slash Redirecting
    features.append(1 if re.search(r"[^/]//", url) else -1)

    # 6. Prefix-Suffix
    features.append(1 if '-' in domain else -1)

    # 7. Subdomain
    subdomain_count = domain.count('.')
    features.append(1 if subdomain_count > 2 else 0 if subdomain_count == 2 else -1)

    # 8. SSL Final State
    features.append(-1 if url.startswith('https://') else 1)

    # 9. Domain Registration Length - check expiration date
    try:
        if whois_data and whois_data.expiration_date and whois_data.updated_date:
            exp = whois_data.expiration_date
            upd = whois_data.updated_date
            
            # Handle both single dates and lists of dates
            if isinstance(exp, list): exp = exp[0]
            if isinstance(upd, list): upd = upd[0]
            
            duration = (exp - upd).days
            features.append(1 if duration <= 365 else -1)
        else:
            features.append(1)  # Default to suspicious if no WHOIS data
    except:
        features.append(1)  # Default to suspicious on error

    # 10. Favicon external
    try:
        if soup:
            icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
            if icon and icon.get('href'):
                features.append(1 if domain not in icon['href'] else -1)
            else:
                features.append(-1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 11. Port
    features.append(1 if re.search(r":[0-9]{2,5}", domain) else -1)

    # 12. HTTPS token in domain
    features.append(1 if 'https' in domain.lower() else -1)

    # 13. Request URL external content (e.g., images/scripts)
    try:
        if soup:
            external_resources = 0
            total_resources = 0
            for tag in soup.find_all(['img', 'script'], src=True):
                total_resources += 1
                if domain not in tag.get('src', ''):
                    external_resources += 1
            
            ratio = external_resources / total_resources if total_resources > 0 else 0
            features.append(1 if ratio > 0.66 else 0 if ratio > 0.33 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 14. URL of Anchor
    try:
        if soup:
            anchors = soup.find_all('a', href=True)
            suspicious = 0
            total = len(anchors)
            
            if total > 0:
                for anchor in anchors:
                    href = anchor.get('href', '')
                    if href.startswith('#') or 'javascript:' in href or not href:
                        suspicious += 1
                    elif domain not in href and not href.startswith('/'):
                        suspicious += 1
                
                ratio = suspicious / total
                features.append(1 if ratio > 0.66 else 0 if ratio > 0.33 else -1)
            else:
                features.append(0)  # Neutral if no anchors
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 15. Links in tags
    try:
        if soup:
            total = 0
            external = 0
            for tag in soup.find_all(['link', 'script', 'meta']):
                src = tag.get('src', tag.get('href', tag.get('content', '')))
                if src:
                    total += 1
                    if domain not in src and not src.startswith('/'):
                        external += 1
            
            ratio = external / total if total > 0 else 0
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
                if 'action' not in f.attrs or f.get('action', '') == '' or f.get('action', '') == 'about:blank':
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

    # 19. Redirect count - use existing response if available
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
    features.append(1 if html and (\"event.button==2\" in html or \"event.button=2\" in html) else -1)

    # 22. Popup
    features.append(1 if html and "window.open" in html else -1)

    # 23. iframe
    features.append(1 if soup and soup.find("iframe") else -1)

    # 24. Age of domain - use WHOIS data if available
    try:
        if whois_data and whois_data.creation_date:
            creation = whois_data.creation_date
            if isinstance(creation, list): creation = creation[0]
            age = (datetime.now() - creation).days
            features.append(1 if age < 180 else -1)
        else:
            features.append(1)  # Default to suspicious if no creation date
    except:
        features.append(-1)

    # 25. DNS record - limit requests
    if external_request_count < MAX_EXTERNAL_REQUESTS:
        try:
            socket.gethostbyname(domain)
            external_request_count += 1
            features.append(-1)  # Domain exists
        except:
            features.append(1)  # Domain doesn't exist
    else:
        features.append(1)  # Default to suspicious if max requests reached

    # 26. Web Traffic - skip making a new request if we already tested the domain
    features.append(0)  # Neutral score instead of making another risky request

    # 27. Page Rank (simulate with number of anchor tags with hrefs)
    try:
        if soup:
            anchors = soup.find_all('a', href=True)
            features.append(1 if len(anchors) > 50 else 0 if 10 < len(anchors) <= 50 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 28. Google Index - avoid making external search requests
    features.append(0)  # Use neutral score instead of making potentially blocked request

    # 29. Links pointing to page (estimate with anchor tags)
    try:
        if soup:
            backlinks = [a for a in soup.find_all('a', href=True) if full_domain in a['href']]
            features.append(1 if len(backlinks) > 5 else 0 if len(backlinks) > 1 else -1)
        else:
            features.append(1)  # Default to suspicious if no soup
    except:
        features.append(-1)

    # 30. Statistical report - check domain against blocklist
    features.append(1 if domain in DOMAIN_BLOCKLIST else -1)

    return features