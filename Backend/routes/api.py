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
from flask_cors import CORS

api_bp = Blueprint("api", __name__)
CORS(api_bp)

UPLOAD_FOLDER = 'uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def validate_llm_output(llm_text):
    """
    Validates and sanitizes the LLM output to prevent potential security issues.
    
    Args:
        llm_text (str): The text output from the LLM
        
    Returns:
        str: Sanitized output
    """
    # Check if the text is valid
    if not isinstance(llm_text, str):
        return "Invalid LLM response format"
    
    if len(llm_text) > 10000:  # Maximum reasonable size
        return "LLM response too large"
    
    # Basic sanitization - remove any potentially harmful content
    sanitized = re.sub(r'<script.*?>.*?</script>', '', llm_text, flags=re.DOTALL)
    sanitized = re.sub(r'<iframe.*?>.*?</iframe>', '', sanitized, flags=re.DOTALL)
    sanitized = re.sub(r'javascript:', '', sanitized, flags=re.IGNORECASE)
    
    # Additional validation could be implemented here based on expected LLM output format
    
    return sanitized

# Reusable logic for checking a URL
def check_url_logic(url: str):
    features = extract_features_from_url(url)
    result = predict_from_features(features)
    feature_dict = dict(zip(FEATURE_NAMES, features))
    llm_result = generate_response(url)
    llm_summary = llm_result.get("summary", "LLM response unavailable")
    
    # Validate and sanitize LLM output before using it
    sanitized_summary = validate_llm_output(llm_summary)

    return {
        "url": url,
        "features": feature_dict,
        "prediction": result["prediction"],
        "confidence": f"{result['confidence']}%",
        "llm_report": sanitized_summary
    }

@api_bp.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400
        
    # URL validation
    url = url.strip()
    
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
        ip_pattern = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'
        is_ip = bool(re.match(ip_pattern, domain_part))
        
        # If not an IP, ensure it has a valid domain format
        if not is_ip and (not domain_part or '.' not in domain_part or len(domain_part.split('.')) < 2):
            return jsonify({"error": "Invalid domain in URL"}), 400
    except Exception:
        return jsonify({"error": "Invalid URL format"}), 400

    try:
        result = check_url_logic(url)
        return jsonify(result)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

@api_bp.route('/upload_image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_image_file(file.filename):
        timestamp = int(time.time())
        filename = f"{timestamp}_{secure_filename(file.filename)}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)

        try:
            # OCR
            image = Image.open(filepath)
            text = pytesseract.image_to_string(image)

            # Extract URLs
            url_pattern = r'((https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/\S*)?)'
            urls = re.findall(url_pattern, text)
            urls = [match[0] for match in urls if match[0]]

            if not urls:
                return jsonify({
                    "text": text,
                    "urls": [],
                    "message": "No URL found in image."
                }), 200

            selected_url = urls[0]
            result = check_url_logic(selected_url)

            return jsonify({
                "text": text,
                "urls": urls,
                "selected_url": selected_url,
                **result,
                "message": "Image processed, URL scanned, and results returned"
            }), 200

        except Exception as e:
            return jsonify({'error': f"OCR or LLM failed: {str(e)}"}), 500

        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

    else:
        return jsonify({'error': 'Invalid image file type'}), 400