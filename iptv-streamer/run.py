# run.py
import sys
import os

# Add project root to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

if __name__ == "__main__":
    try:
        from app.routes import app
        print("✅ App imported successfully")
        app.run(host="0.0.0.0", port=8000, debug=True, use_reloader=False)
    except Exception as e:
        print("❌ FATAL ERROR:", str(e))
        import traceback
        traceback.print_exc()
        sys.exit(1)
