
from flask import Flask, render_template, request, jsonify
from scanner import scan_url
from urllib.parse import urlparse, urlencode, urlunparse, parse_qs
import json
from datetime import datetime
import os

app = Flask(__name__)
HISTORY_FILE = "scan_history.json"

def save_history(entry):
    history = []
    if os.path.exists(HISTORY_FILE):
        with open(HISTORY_FILE, "r") as f:
            history = json.load(f)
    history.append(entry)
    with open(HISTORY_FILE, "w") as f:
        json.dump(history, f, indent=4)

def get_history():
    if not os.path.exists(HISTORY_FILE):
        return []
    with open(HISTORY_FILE, "r") as f:
        return json.load(f)

def build_url_with_param(url, param="id", value="1"):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    query[param] = value
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form.get("url")
        category = request.form.get("category", "all")
        if url and url.startswith("http"):
            parsed = urlparse(url)
            safe_url = url if parsed.query else build_url_with_param(url)
            result = scan_url(safe_url, category)
            entry = {
                "url": safe_url,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "result": result
            }
            save_history(entry)
        else:
            result = {"error": "Invalid URL"}
    return render_template("index.html", result=result)

@app.route("/history")
def history():
    return render_template("history.html", history=get_history())

@app.route("/api/scan", methods=["POST"])
def api_scan():
    data = request.json
    url = data.get("url")
    category = data.get("category", "all")
    if url and url.startswith("http"):
        parsed = urlparse(url)
        safe_url = url if parsed.query else build_url_with_param(url)
        result = scan_url(safe_url, category)
        return jsonify(result)
    return jsonify({"error": "Invalid or missing URL"}), 400

if __name__ == "__main__":
    app.run(debug=True)
