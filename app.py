from flask import Flask, request, jsonify
from flask_cors import CORS  # Import CORS
import requests
import time
from bs4 import BeautifulSoup

app = Flask(__name__)
CORS(app) 
# Function to scan website
def scan_website(url):
    start_time = time.time()
    scan_result = {
        "url": url,
        "vulnerabilities": {
            "XSS": False,
            "SQL_Injection": False,
            "CSRF": False,
            "Other": []
        },
        "risk_score": 0,
        "scan_time": 0
    }

    # Check for XSS
    def check_xss(url):
        try:
            response = requests.get(url)
            if "<script>" in response.text:
                return True
        except requests.exceptions.RequestException:
            return False
        return False

    # Check for SQL Injection
    def check_sql_injection(url):
        try:
            response = requests.get(url + "' OR '1'='1")
            if "SQL" in response.text or "syntax error" in response.text:
                return True
        except requests.exceptions.RequestException:
            return False
        return False

    # Check for CSRF
    def check_csrf(url):
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, "html.parser")
            forms = soup.find_all("form")
            for form in forms:
                if not form.find("input", {"name": "csrf_token"}):
                    return True
        except requests.exceptions.RequestException:
            return False
        return False

    # Perform checks
    if check_xss(url):
        scan_result["vulnerabilities"]["XSS"] = True
        scan_result["risk_score"] += 30

    if check_sql_injection(url):
        scan_result["vulnerabilities"]["SQL_Injection"] = True
        scan_result["risk_score"] += 40

    if check_csrf(url):
        scan_result["vulnerabilities"]["CSRF"] = True
        scan_result["risk_score"] += 20

    scan_result["vulnerabilities"]["Other"].append("Insecure HTTP headers")
    scan_result["risk_score"] += 10

    # Measure scan time
    scan_result["scan_time"] = round(time.time() - start_time, 2)

    return scan_result

# API endpoint to scan the URL
@app.route('/scan', methods=['POST'])
def scan():
    data = request.get_json()
    url = data.get('url')
    print(f"Received URL: {url}")  # Log the received URL
    result = scan_website(url)
    return jsonify(result)


if __name__ == '__main__':
    # app.run(debug=False, port=5001)
    pass
