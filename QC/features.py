# file: features.py

import re
from urllib.parse import urlparse

def extract_features(url: str) -> list[int]:
    parsed = urlparse(url)
    domain = parsed.netloc
    path = parsed.path
    scheme = parsed.scheme

    features = [
        len(url),                                 # 1
        len(domain),                              # 2
        len(path),                                # 3
        url.count('.'),                           # 4
        url.count('-'),                           # 5
        url.count('@'),                           # 6
        url.count('=') + url.count('&'),          # 7
        url.count('?'),                           # 8
        int('//' in url),                         # 9
        int(url.startswith('https://')),          # 10
        int(url.startswith('http://')),           # 11
        int(bool(re.search(r'https', url))),      # 12
        int(bool(re.search(r'\d', url))),         # 13
        sum(c.isdigit() for c in url),            # 14
        sum(c.isalpha() for c in url),            # 15
        len(re.findall(r'[0-9]', url)),           # 16
        len(re.findall(r'[A-Z]', url)),           # 17
        len(re.findall(r'[a-z]', url)),           # 18
        len(re.findall(r'[\W_]', url)),           # 19
        len(set(url)),                            # 20
        int("server" in url.lower()),             # 21
        int("login" in url.lower()),              # 22
        int("admin" in url.lower()),              # 23
        int("client" in url.lower()),             # 24
        int("secure" in url.lower()),             # 25
        int("update" in url.lower()),             # 26
        int("verify" in url.lower()),             # 27
        int("bank" in url.lower()),               # 28
        int("account" in url.lower()),            # 29
        int("free" in url.lower()),               # 30
    ]

    return features
