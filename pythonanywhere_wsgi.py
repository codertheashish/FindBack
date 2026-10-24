# Paste this whole file into the WSGI configuration file on PythonAnywhere (Web tab).
# Replace YOUR_USERNAME with your PythonAnywhere username.
import sys

path = "/home/YOUR_USERNAME/findback"
if path not in sys.path:
    sys.path.insert(0, path)

from app import app as application  # noqa
