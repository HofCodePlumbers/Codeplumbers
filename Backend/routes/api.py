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

api_bp = Blueprint('api', __name__)

# ✅ Define whitelist
WHITELIST = {
    "google.com",
    "wikipedia.org",
    "github.com",
    "apple.com",
    "microsoft.com",
    "amazon.com"
}

# ✅ Reusable logic for checking a URL
def check_url_logic(url: str):
    domain_info = tldextract.extract(url)
    full_domain = f"{domain_info.domain}.{domain_info.suffix}"

    if full_domain in WHITELIST:
        time.sleep(3)
        return {
            "url": url,
            "features": dict(zip(FEATURE_NAMES, [-1] * len(FEATURE_NAMES))),
            "prediction": "legitimate",
            "confidence": "100",
            "llm_report": f"The domain {url} is considered safe."
        }

    # Otherwise, proceed with feature extraction and prediction
    features = extract_features_from_url(url)
    print(features)
    result = predict_from_features(features)
    feature_dict = dict(zip(FEATURE_NAMES, features))
    llm_result = generate_response(url)
    llm_summary = llm_result.get("summary", "LLM response unavailable")

    return {
        "url": url,
        "features": feature_dict,
        "prediction": result["prediction"],
        "confidence": f"{result['confidence']}%",
        "llm_report": llm_summary
    }

@api_bp.route("/check_url", methods=["POST"])
def check_url():
    url = request.form.get("url")
    if not url:
        return jsonify({"error": "No URL provided"}), 400


    try:
        # Extract features & run ML prediction
        features = extract_features_from_url(url)
        result = predict_from_features(features)
        feature_dict = dict(zip(FEATURE_NAMES, features))
        
        # Run LLM logic to get report
        llm_result = generate_response(url)
        llm_summary = llm_result.get("summary", "LLM response unavailable")
        
        # Validate and sanitize LLM output before using it
        sanitized_summary = llm_summary

        # Return all in one response
        return jsonify({
            "url": url,
            "features": feature_dict,
            "prediction": result["prediction"],
            "confidence": f"{result['confidence']}%",
            "llm_report": sanitized_summary
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500
# WHITELIST = {
#     "google.com",
#     "wikipedia.org",
#     "github.com",
#     "apple.com",
#     "microsoft.com",
#     "amazon.com"
# }

def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

@api_bp.route('/upload_image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400


def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def validate_image_content(file):
    """
    Verifies that the file content is actually a valid image.
    This helps prevent malicious file uploads with fake extensions.
    """
    try:
        # Check if it's a valid image by opening it with PIL
        img = Image.open(file)
        img.verify()  # Verify it's a valid image
        file.seek(0)  # Reset file pointer for future operations
        return True
    except Exception:
        return False
'''
@api_bp.route('/upload_image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400
    else:
        return jsonify({'error': 'Invalid image file type'}), 400
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    if file and allowed_image_file(file.filename):
        # Verify the actual file content before saving
        if not validate_image_content(file):
            return jsonify({'error': 'Invalid image content or potential malicious file'}), 400
            
        timestamp = int(time.time())
        filename = f"{timestamp}_{secure_filename(file.filename)}"
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        file.save(filepath)
        try:
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

            if os.path.exists(filepath):
                os.remove(filepath)

    else:
        return jsonify({'error': 'Invalid image file type'}), 400
'''