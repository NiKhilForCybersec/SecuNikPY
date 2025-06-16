#!/usr/bin/env python3
import http.server
import socketserver
import webbrowser
import os
from pathlib import Path

PORT = 3000
DIRECTORY = Path(__file__).parent / "public"

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

try:
    os.chdir(DIRECTORY)
    with socketserver.TCPServer(("", PORT), Handler) as httpd:
        print(f"SecuNik Simple Frontend running at http://localhost:{PORT}")
        print("Press Ctrl+C to stop the server")
        
        # Try to open browser
        try:
            webbrowser.open(f'http://localhost:{PORT}')
        except:
            pass
            
        httpd.serve_forever()
except KeyboardInterrupt:
    print("\nFrontend server stopped")
except OSError as e:
    print(f"Error: Port {PORT} may already be in use. {e}")
