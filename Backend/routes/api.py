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

# Reusable logic for checking a URL
def check_url_logic(url: str):
    features = extract_features_from_url(url)
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
