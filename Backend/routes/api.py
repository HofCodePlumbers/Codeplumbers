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
import html

api_bp = Blueprint("api", __name__)

UPLOAD_FOLDER = 'uploads'
ALLOWED_IMAGE_EXTENSIONS = {'png', 'jpg', 'jpeg', 'bmp'}
ALLOWED_IMAGE_MIMES = {'image/png', 'image/jpeg', 'image/jpg', 'image/bmp'}
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def validate_llm_output(output):
    """
    Validate and sanitize LLM output to prevent manipulation attacks.
    
    Args:
        output (str): Raw LLM output
        
    Returns:
        str: Sanitized LLM output
    """
    if not output or not isinstance(output, str):
        return "Invalid LLM response format"
    
    # Limit length to prevent DoS
    if len(output) > 5000:
        output = output[:5000] + "... (truncated)"
        
    # Escape HTML to prevent XSS if the output is used in a web context
    sanitized_output = html.escape(output)
    
    # Additional validation can be implemented based on specific requirements
    # For example, checking for malicious patterns, removing unwanted content, etc.
    
    return sanitized_output

@api_bp.route("/check_url", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    if not url:
        return jsonify({"error": "No URL provided"}), 400

    try:
        # Extract features & run ML prediction
        features = extract_features_from_url(url)
        result = predict_from_features(features)
        feature_dict = dict(zip(FEATURE_NAMES, features))

        # Run LLM logic to get report
        llm_result = generate_response(url)
        raw_llm_summary = llm_result.get("summary", "LLM response unavailable")
        
        # Validate and sanitize the LLM output
        validated_llm_summary = validate_llm_output(raw_llm_summary)

        # Return all in one response
        return jsonify({
            "url": url,
            "features": feature_dict,
            "prediction": result["prediction"],
            "confidence": f"{result['confidence']}%",
            "llm_report": validated_llm_summary
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


def allowed_image_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_IMAGE_EXTENSIONS

def is_valid_image(file):
    # Check the file content to verify it's actually an image
    try:
        # Save position for resetting later
        position = file.tell()
        
        # Try to open the file as an image
        img = Image.open(file)
        img.verify()  # Verify it's an image
        
        # Reset file position
        file.seek(position)
        return True
    except Exception:
        # Reset file position even if verification fails
        file.seek(position)
        return False

@api_bp.route('/upload_image', methods=['POST'])
def upload_image():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in request'}), 400

    file = request.files['file']
    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # First, check file extension
    if not allowed_image_file(file.filename):
        return jsonify({'error': 'Invalid image file type'}), 400
        
    # Second, check MIME type
    if file.content_type not in ALLOWED_IMAGE_MIMES:
        return jsonify({'error': 'Invalid image content type'}), 400
        
    # Third, verify it's a valid image by checking content
    if not is_valid_image(file):
        return jsonify({'error': 'File is not a valid image'}), 400

    # If it passes all checks, proceed with saving and processing
    timestamp = int(time.time())
    filename = f"{timestamp}_{secure_filename(file.filename)}"
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    try:
        # OCR
        image = Image.open(filepath)
        text = pytesseract.image_to_string(image)

        # Extract URLs using regex
        url_pattern = r'((https?:\/\/)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(\/\S*)?)'
        urls = re.findall(url_pattern, text)
        urls = [match[0] for match in urls if match[0]]

        # Return the response before deleting the file
        return jsonify({
            "text": text,
            "urls": urls,
            "file": filename,
            "message": "Image processed and OCR completed"
        }), 200

    except Exception as e:
        return jsonify({'error': f"OCR failed: {str(e)}"}), 500

    finally:
        # Always delete the file
        if os.path.exists(filepath):
            os.remove(filepath)