# wsgi.py
import sys
import os

# Add current directory to Python path
sys.path.insert(0, os.path.dirname(__file__))

from app.routes import app

if __name__ == "__main__":
    app.run()
