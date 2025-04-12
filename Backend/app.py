from flask import Flask
from routes.api import api_bp
import os

app = Flask(__name__)
app.register_blueprint(api_bp, url_prefix="/api")

if __name__ == '__main__':
    # Use environment variable to control debug mode
    # Default to False for security in production
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)