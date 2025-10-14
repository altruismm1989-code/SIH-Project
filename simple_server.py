# Create simple_server.py
from flask import Flask, send_file

app = Flask(__name__)

@app.route('/')
def dashboard():
    return send_file('cctv_dashboard.html')

if __name__ == '__main__':
    app.run(debug=True, port=5000)