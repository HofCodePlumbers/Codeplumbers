from flask import Flask
from routes.api import api_bp
import os

app = Flask(__name__)
app.register_blueprint(api_bp, url_prefix="/api")

if __name__ == '__main__':
    # Enable debug mode only in development environment
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)
    # Enable debug mode only in development environment
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(debug=debug_mode)
    debug_mode = os.environ.get('FLASK_DEBUG', 'False').lower() == 'true'
    app.run(debug=debug_mode)
