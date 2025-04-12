from flask import Flask
from routes.api import api_bp
import os

app = Flask(__name__)
app.register_blueprint(api_bp, url_prefix="/api")

if __name__ == '__main__':
    # Security: Debug mode should never be enabled in production environments as it can expose
    # sensitive information through detailed error pages and stack traces
    
    # Enable debug mode only in development environment
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    
    # Single app.run() call with controlled debug mode
    app.run(debug=debug_mode)