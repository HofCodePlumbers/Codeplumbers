from flask import Flask
from routes.api import api_bp
import os

app = Flask(__name__)
app.register_blueprint(api_bp, url_prefix="/api")

if __name__ == '__main__':
    # Set debug mode based on environment variable, default to False for safety
    debug_mode = os.environ.get('FLASK_ENV') == 'development'
    app.run(ssl_context=('cert.pem', 'key.pem'), debug=debug_mode)