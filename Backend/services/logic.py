import re
import requests
import socket
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup

OLLAMA_URL = 'http://localhost:11434/api/generate'

def is_url_safe(url):
    """
    Check if the URL is safe to access:
    - Must be HTTP or HTTPS
    - Must not point to private IP ranges, localhost, or internal network resources
    """
    try:
        parsed_url = urlparse(url)
        
        # Ensure the scheme is http or https
        if parsed_url.scheme not in ['http', 'https']:
            return False
        
        # Extract the hostname
        hostname = parsed_url.netloc
        
        # Remove port number if present
        if ':' in hostname:
            hostname = hostname.split(':')[0]
        
        # Blocklist check for common internal hostnames
        blocklist = ['localhost', '127.0.0.1', '0.0.0.0', '::1', '[::1]']
        if hostname.lower() in blocklist or hostname.endswith(('.local', '.internal', '.intranet')):
            return False
        
        # Check if hostname is an IP address
        try:
            ip = ipaddress.ip_address(hostname)
            # Check if IP is private, loopback, etc.
            if (ip.is_private or ip.is_loopback or ip.is_link_local or 
                ip.is_multicast or ip.is_reserved or ip.is_unspecified):
                return False
        except ValueError:
            # Not an IP address in the hostname, which is okay
            pass
        
        # Check if hostname is a domain with DNS resolution
        try:
            resolved_ip = socket.gethostbyname(hostname)
            ip_obj = ipaddress.ip_address(resolved_ip)
            if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
                ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
                return False
        except (socket.gaierror, ValueError):
            # If DNS resolution fails or IP is invalid, we'll allow it
            # as it might be a valid hostname that just can't be resolved
            pass
        
        return True
        
    except Exception:
        return False

def sanitize_for_prompt(text):
    """
    Sanitize text before including it in prompts to prevent adversarial manipulation.
    """
    if not text or not isinstance(text, str):
        return ""
    
    # Remove control characters and potential prompt injection patterns
    sanitized = re.sub(r'[^\x20-\x7E\s]', '', text)  # Keep only printable ASCII and whitespace
    
    # Remove patterns that might be used for prompt injection
    injection_patterns = [
        r'<\s*prompt\s*>.*?<\s*/\s*prompt\s*>',
        r'<\s*system\s*>.*?<\s*/\s*system\s*>',
        r'<\s*instruction\s*>.*?<\s*/\s*instruction\s*>'
    ]
    for pattern in injection_patterns:
        sanitized = re.sub(pattern, '[REMOVED]', sanitized, flags=re.IGNORECASE | re.DOTALL)
    
    # Truncate to prevent overwhelming the model
    max_length = 4000  # Reasonable limit for a section of the prompt
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "... [truncated]"
    
    return sanitized

def duckduckgo_check(domain):
    import requests
    from bs4 import BeautifulSoup

    query = f"https://duckduckgo.com/html/?q={domain}"
    headers = {
        "User-Agent": "Mozilla/5.0"
    }

    try:
        resp = requests.get(query, headers=headers)
        soup = BeautifulSoup(resp.text, "html.parser")

        snippets = " ".join([result.text for result in soup.select(".result__snippet")])
        keywords = ["scam", "fraud", "fake", "phishing", "complaint", "not legit", "ripoff"]
        found = [k for k in keywords if k in snippets.lower()]

        return {
            "is_suspicious": len(found) >= 2,
            "matched_keywords": found
        }

    except Exception as e:
        return {
            "is_suspicious": False,
            "matched_keywords": [],
            "error": str(e)
        }


def fetch_website_text(url):
    # Ensure URL has a scheme
    if not url.startswith("http://") and not url.startswith("https://"):
        url = "http://" + url  # Add default scheme if missing
    
    # Validate URL is safe to access
    if not is_url_safe(url):
        return "[Error: Cannot access internal or private network resources]"
    
    try:
        response = requests.get(url, timeout=5)
        response.raise_for_status()
        soup = BeautifulSoup(response.text, 'html.parser')
        return soup.get_text(separator='\n', strip=True)
    except Exception as e:
        return f"[Error fetching website: {e}]"

def extract_summary(response_text):
    # Remove <think>...</think> block if it exists
    return re.sub(r"<think>.*?</think>\s*", "", response_text, flags=re.DOTALL).strip()

def generate_response(url):
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path  # fallback if scheme is missing
    safe_domain = sanitize_for_prompt(domain)

    # --- Step 1: DuckDuckGo keyword check ---
    duck_result = duckduckgo_check(domain)
    search_summary = ""
    if duck_result["is_suspicious"]:
        safe_keywords = [sanitize_for_prompt(keyword) for keyword in duck_result['matched_keywords']]
        search_summary = (
            f"\nSearch engine results indicate the domain may be suspicious. "
            f"Found keywords: {', '.join(safe_keywords)}.\n"
        )
    safe_search_summary = sanitize_for_prompt(search_summary)

    # --- Step 2: Fetch website content ---
    website_text = fetch_website_text(url)
    safe_website_text = sanitize_for_prompt(website_text)

    # --- Step 3: Create prompt for Ollama ---
    prompt = f"""
You are a cybersecurity AI assistant helping users evaluate the safety and legitimacy of websites.

A user has asked you to analyze this domain: {safe_domain}

Your tasks are:
1. Analyze the domain name structure and determine if it appears to impersonate a legitimate organization (e.g., government agency, company, university, or service).
2. Judge if the domain name uses typosquatting, brand impersonation, or misleading patterns to appear trustworthy.
3. Determine from online search results and website content whether the site is linked to known scams or phishing behavior.
4. Say whether it appears to be from an official or trustworthy source — or is pretending to be.
5. Summarize all findings clearly in a short paragraph, including why the site is or is not trustworthy.

Search engine findings:
{safe_search_summary or "No clear scam indicators were found in web search."}

Website content:
---
{safe_website_text}
---

Give your assessment now.
"""


    payload = {
        "model": "deepseek-r1:latest",
        "prompt": prompt,
        "stream": False
    }

    try:
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        raw_text = response.json().get("response", "")
        return {"summary": extract_summary(raw_text)}
    except requests.RequestException as e:
        return {"error": str(e)}