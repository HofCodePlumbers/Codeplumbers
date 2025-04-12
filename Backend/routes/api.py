from flask import Blueprint, request, jsonify
from services.url_features import extract_features_from_url, FEATURE_NAMES
from ml.phishing_model import predict_from_features
from services.logic import generate_response
import os
from werkzeug.utils import secure_filename
from PIL import Image
import pytesseract
import time
import re
from urllib.parse import urlparse
import tldextract
from flask_cors import CORS
UPLOAD_FOLDER = 'uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def validate_llm_output(llm_text):
    """
    Validates and sanitizes the LLM output to prevent potential security issues.
    Uses a comprehensive approach to ensure outputs can't be used for XSS or other attacks.
    """
    if not isinstance(llm_text, str):
        return "Invalid LLM response format"
    
    if len(llm_text) > 10000:  # Maximum reasonable size
        return "LLM response too large"
    
    # First remove any HTML tags completely
    sanitized = re.sub(r'<[^>]*>', '', llm_text)
    
    # Manually escape HTML special characters
    sanitized = sanitized.replace('&', '&amp;')
    sanitized = sanitized.replace('<', '&lt;')
    sanitized = sanitized.replace('>', '&gt;')
    sanitized = sanitized.replace('"', '&quot;')
    sanitized = sanitized.replace("'", '&#x27;')
    
    # Return the sanitized output
    return sanitized

    """
    if not isinstance(llm_text, str):
        return "Invalid LLM response format"
    
    if len(llm_text) > 10000:  # Maximum reasonable size
    
    # Check URL length to prevent DoS
    if len(url) > 2048:
        return jsonify({"error": "URL exceeds maximum allowed length"}), 400
        
    # Basic protocol validation
    if not url.startswith(('http://', 'https://')):
        return jsonify({"error": "URL must use HTTP or HTTPS protocol"}), 400
    
    # Extract and validate domain
    try:
        domain_part = url.split('://', 1)[1].split('/', 1)[0].split(':', 1)[0]  # Handle ports
        
        # Check if domain is an IP address
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)