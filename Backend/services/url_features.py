import re
import requests
import socket
import whois
import tldextract
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime

FEATURE_NAMES = [
    "having_IP_Address", "URL_Length", "Shortening_Service", "having_At_Symbol",
    "double_slash_redirecting", "Prefix_Suffix", "having_Sub_Domain", "SSLfinal_State",
    "Domain_registeration_length", "Favicon", "port", "HTTPS_token", "Request_URL",
    "URL_of_Anchor", "Links_in_tags", "SFH", "Submitting_to_email", "Abnormal_URL",
    "Redirect", "on_mouseover", "RightClick", "popUpWidnow", "Iframe",
    "age_of_domain", "DNSRecord", "Web_Traffic", "Page_Rank", "Google_Index",
    "Links_pointing_to_page", "Statistical_report"
]

# ✅ Whitelist of known safe domains
WHITELIST = {
    "google.com",
    "wikipedia.org",
    "github.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    # Add more if needed
}

def extract_features_from_url(url):
    features = []
    parsed = urlparse(url)
    domain = parsed.netloc
    domain_info = tldextract.extract(url)
    full_domain = f"{domain_info.domain}.{domain_info.suffix}"
    path = parsed.path

    # ✅ Whitelist override
    if full_domain in WHITELIST:
        print(f"[INFO] {full_domain} is whitelisted. Skipping feature extraction.")
        return [-1] * len(FEATURE_NAMES)

    # Request page content
    try:
        response = requests.get(url, timeout=5)
        html = response.text
        soup = BeautifulSoup(html, 'html.parser')
    except:
        html = ""
        soup = None

    # WHOIS data
    try:
        whois_data = whois.whois(full_domain)
    except:
        whois_data = None

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
        icon = soup.find("link", rel=lambda x: x and 'icon' in x.lower())
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
        total = 0
        external = 0
        for tag in soup.find_all(['img', 'script'], src=True):
            total += 1
            if domain not in tag['src']:
                external += 1
        ratio = external / total if total else 0
        features.append(1 if ratio > 0.61 else 0 if 0.22 < ratio <= 0.61 else -1)
    except:
        features.append(-1)

    # 14. Anchor tags pointing elsewhere
    try:
        anchors = soup.find_all('a', href=True)
        total = len(anchors)
        unsafe = sum(1 for a in anchors if "#" in a['href'] or "javascript" in a['href'].lower())
        ratio = unsafe / total if total else 0
        features.append(1 if ratio > 0.67 else 0 if 0.31 < ratio <= 0.67 else -1)
    except:
        features.append(-1)

    # 15. Meta/script/link tags external
    try:
        tags = soup.find_all(['meta', 'script', 'link'])
        total = len(tags)
        unsafe = sum(1 for tag in tags if domain not in str(tag))
        ratio = unsafe / total if total else 0
        features.append(1 if ratio > 0.81 else 0 if 0.17 < ratio <= 0.81 else -1)
    except:
        features.append(-1)

    # 16. SFH (server form handler)
    try:
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
    except:
        features.append(-1)

    # 17. Submitting to email
    features.append(1 if "mailto:" in html else -1)

    # 18. Abnormal URL
    features.append(1 if domain not in url else -1)

    # 19. Redirect count
    try:
        r = requests.get(url, timeout=5)
        features.append(1 if len(r.history) > 3 else 0 if len(r.history) else -1)
    except:
        features.append(-1)

    # 20. onmouseover
    features.append(1 if "onmouseover" in html else -1)

    # 21. Right click disabled
    features.append(1 if "event.button==2" in html else -1)

    # 22. Popup
    features.append(1 if "window.open" in html else -1)

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

    # 25. DNS record
    try:
        socket.gethostbyname(domain)
        features.append(-1)
    except:
        features.append(1)

    # 26. Web Traffic (simulate with reachability check)
    try:
        traffic = requests.get(f"https://www.{full_domain}", timeout=5)
        features.append(1 if traffic.status_code == 200 else -1)
    except:
        features.append(-1)

    # 27. Page Rank (simulate with number of anchor tags with hrefs)
    try:
        anchors = soup.find_all('a', href=True)
        features.append(1 if len(anchors) > 50 else 0 if 10 < len(anchors) <= 50 else -1)
    except:
        features.append(-1)

    # 28. Google Index (try searching site:domain using Google)
    try:
        search_url = f"https://www.google.com/search?q=site:{full_domain}"
        headers = {"User-Agent": "Mozilla/5.0"}
        result = requests.get(search_url, headers=headers, timeout=5)
        features.append(1 if "did not match any documents" not in result.text else -1)
    except:
        features.append(-1)

    # 29. Links pointing to page (simulate by counting backlinks in soup)
    try:
        backlinks = [a for a in soup.find_all('a', href=True) if full_domain in a['href']]
        features.append(1 if len(backlinks) > 5 else 0 if len(backlinks) > 1 else -1)
    except:
        features.append(-1)

    # 30. Statistical report (real domain/URL check against PhishTank-style blacklist)
    try:
        blacklist = ['malwaredomainlist.com', 'phishtank.org', 'stopbadware.org', 'clean-mx.com', 'malc0de.com']
        features.append(1 if any(b in url for b in blacklist) else -1)
    except:
        features.append(-1)

    return features
