import re
import requests
import socket
import ipaddress
from urllib.parse import urlparse
from bs4 import BeautifulSoup

OLLAMA_URL = 'http://localhost:11434/api/generate'
MAX_CONTENT_LENGTH = 4000

def is_valid_url(url):
    """Simple URL validation without external dependencies."""
    if not url or not isinstance(url, str):
        return False
    
    # Add http:// prefix if missing for validation purposes
    check_url = url
    if not url.startswith(('http://', 'https://')):
        check_url = 'http://' + url
    
    try:
        result = urlparse(check_url)
        # Check if domain is present
        return all([result.scheme, result.netloc])
    except:
        return False

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
            # Check if the resolved IP is private, loopback, etc.
            if (ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local or 
                ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified):
                return False
        except (socket.gaierror, ValueError):
            # Unable to resolve hostname or resolved to invalid IP
            # Allow it to continue, since some valid domains might not resolve
            pass
        
        return True
    except Exception:
        # Any unhandled exception is a security risk
        return False

def sanitize_for_prompt(text):
    """Sanitize text to be safely included in an AI prompt."""
    if not text:
        return ""
    
    # Strip any control characters
    text = re.sub(r'[\x00-\x1F\x7F]', '', text)
    
    # Handle potential prompt injection markers
    text = re.sub(r'\[(?:SYSTEM|USER|ASSISTANT|INSTRUCTION|SEARCH|WEBSITE|END).*?\]', 
                  lambda m: '\\' + m.group(0), text, flags=re.IGNORECASE)
    
    return text

def duckduckgo_check(domain):
    """
    Check if a domain is suspicious based on DuckDuckGo search results.
    Returns a dictionary with suspicion status and matched keywords if any.
    """
    suspicious_keywords = [
        "scam", "fraud", "phishing", "malware", "virus", 
        "spam", "malicious", "fake", "suspicious"
    ]
    
    try:
        search_url = f"https://html.duckduckgo.com/html/?q={domain}+review+scam"
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }
        
        # Validate the search URL is safe before proceeding
        if not is_url_safe(search_url):
            return {"is_suspicious": False, "matched_keywords": [], "error": "Search URL considered unsafe"}
        
        response = requests.get(search_url, headers=headers, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        results = soup.find_all("a", class_="result__snippet")
        
        matched_keywords = []
        for result in results[:5]:  # Check first 5 results
            text = result.get_text().lower()
            for keyword in suspicious_keywords:
                if keyword in text and keyword not in matched_keywords:
                    matched_keywords.append(keyword)
        
        return {
            "is_suspicious": len(matched_keywords) > 0,
            "matched_keywords": matched_keywords
        }
    except Exception as e:
        return {"is_suspicious": False, "matched_keywords": [], "error": str(e)}

def fetch_website_text(url):
    """Fetch and extract text content from a website."""
    try:
        # Validate URL is safe to access before making the request
        if not is_url_safe(url):
            return "[Error: URL is not safe to access]"
        
        # Set a reasonable timeout to prevent abuse
        response = requests.get(url, headers={
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
        }, timeout=10)
        
        response.raise_for_status()
        
        # Use BeautifulSoup to extract text content
        soup = BeautifulSoup(response.text, 'html.parser')
        
        # Remove script and style elements
        for script in soup(["script", "style", "meta", "noscript"]):
            script.decompose()
        
        # Get text and remove excessive whitespace
        text = soup.get_text(separator=' ')
        text = re.sub(r'\s+', ' ', text).strip()
        
        return text[:MAX_CONTENT_LENGTH]  # Limit length to prevent abuse
    except requests.RequestException as e:
        return f"[Error fetching website: {str(e)}]"
    except Exception as e:
        return f"[Error processing website content: {str(e)}]"

def extract_summary(response_text):
    # Remove <think>...</think> block if it exists
    return re.sub(r"<think>.*?</think>\s*", "", response_text, flags=re.DOTALL).strip()

def generate_response(url):
    # Validate input URL
    if not url or not isinstance(url, str):
        return {"error": "Invalid URL provided"}
    
    # Perform basic URL validation
    if not is_valid_url(url):
        return {"error": "Malformed or invalid URL"}
    
    # Ensure URL is safe (no SSRF vulnerabilities)
    if not is_url_safe(url):
        return {"error": "URL points to an internal or restricted resource"}
    
    parsed = urlparse(url)
    domain = parsed.netloc or parsed.path  # fallback if scheme is missing
    
    # Sanitize domain and URL for prompt inclusion
    safe_domain = sanitize_for_prompt(domain)
    safe_url = sanitize_for_prompt(url)
    
    if not safe_domain:
        return {"error": "Invalid domain in URL"}

    # --- Step 1: DuckDuckGo keyword check ---
    duck_result = duckduckgo_check(safe_domain)
    search_summary = ""
    if duck_result.get("is_suspicious", False):
        search_summary = (
            f"\nSearch engine results indicate the domain may be suspicious. "
            f"Found keywords: {', '.join(duck_result.get('matched_keywords', []))}.\n"
        )

    # --- Step 2: Fetch website content ---
    website_text = fetch_website_text(url)
    
    # Sanitize website content for prompt inclusion
    safe_website_text = sanitize_for_prompt(website_text)
    
    # Limit content length to prevent token overflow
    safe_website_text = safe_website_text[:MAX_CONTENT_LENGTH]

    # --- Step 3: Create prompt for Ollama with clear boundaries ---
    prompt = f"""
You are a cybersecurity AI assistant helping users evaluate the safety and legitimacy of websites.

[SYSTEM INSTRUCTION]
A user has asked you to analyze this domain: {safe_url}

Your tasks are:
1. Analyze the domain name structure and determine if it appears to impersonate a legitimate organization (e.g., government agency, company, university, or service).
2. Judge if the domain name uses typosquatting, brand impersonation, or misleading patterns to appear trustworthy.
3. Determine from online search results and website content whether the site is linked to known scams or phishing behavior.
4. Say whether it appears to be from an official or trustworthy source — or is pretending to be.
5. Summarize all findings clearly in a short paragraph, including why the site is or is not trustworthy.
[END SYSTEM INSTRUCTION]

[SEARCH RESULTS]
{search_summary or "No clear scam indicators were found in web search."}
[END SEARCH RESULTS]

[WEBSITE CONTENT]
{safe_website_text}
[END WEBSITE CONTENT]

Based on the information above, provide your assessment of the website.
"""

    payload = {
        "model": "deepseek-r1:latest",
        "prompt": prompt,
        "stream": False
    }

    try:
        # Ensure AI service URL is also safe (important for localhost services)
        if not is_url_safe(OLLAMA_URL) and not OLLAMA_URL.startswith('http://localhost:'):
            return {"error": "AI service URL is restricted"}
        
        response = requests.post(OLLAMA_URL, json=payload)
        response.raise_for_status()
        raw_text = response.json().get("response", "")
        return {"summary": extract_summary(raw_text)}
    except requests.RequestException as e:
        return {"error": str(e)}