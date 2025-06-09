
import requests
import json
import time
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor

with open("payloads.json", "r") as f:
    payloads = json.load(f)

error_signatures = [
    "sql syntax", "mysql_fetch", "ORA-01756", "ODBC", "unterminated",
    "query failed", "you have an error", "unexpected token", "Warning: pg_",
    "Fatal error", "Unclosed quotation", "invalid query", "Unknown column"
]

def inject_payload(url, param, payload):
    parsed = urlparse(url)
    query = parse_qs(parsed.query)
    original_value = query.get(param, [""])[0]
    query[param] = original_value + payload
    new_query = urlencode(query, doseq=True)
    return urlunparse(parsed._replace(query=new_query))

def assess_severity(reason):
    if "time-based" in reason.lower():
        return "high"
    elif "error" in reason.lower():
        return "medium"
    elif "content differs" in reason.lower():
        return "low"
    return "info"

def test_payload(url, original_text, param, payload_data):
    payload = payload_data["payload"]
    category = payload_data.get("category", "uncategorized")
    test_url = inject_payload(url, param, payload)

    try:
        start = time.time()
        r = requests.get(test_url, timeout=10)
        end = time.time()
        delay = round(end - start, 2)
        is_time_delay = "sleep" in payload.lower() and delay >= 3.5

        status = "safe"
        reason = ""
        response_diff = abs(len(original_text) - len(r.text))

        for err in error_signatures:
            if err.lower() in r.text.lower():
                status = "vulnerable"
                reason = "SQL error detected"
                break

        if status != "vulnerable" and response_diff > 100:
            status = "vulnerable"
            reason = "Response content differs significantly"

        if is_time_delay:
            status = "vulnerable"
            reason = "Time-based delay detected"

        if status == "vulnerable":
            return {
                "url": test_url,
                "param": param,
                "payload": payload,
                "category": category,
                "reason": reason,
                "response_time": delay,
                "severity": assess_severity(reason)
            }
    except:
        pass
    return None

def scan_url(url, category="all"):
    parsed = urlparse(url)
    if not parsed.query:
        return {"error": "URL must have query parameters (e.g., ?id=1)"}

    original_response = requests.get(url)
    original_text = original_response.text
    results = []
    total_start = time.time()

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        for p in payloads:
            if category != "all" and p.get("category", "uncategorized") != category:
                continue
            for param in parse_qs(parsed.query):
                futures.append(executor.submit(test_payload, url, original_text, param, p))

        for future in futures:
            result = future.result()
            if result:
                results.append(result)

    total_end = time.time()
    return {
        "target": url,
        "vulnerabilities": results,
        "scan_time": round(total_end - total_start, 2),
        "payloads_used": len(payloads),
        "parameters_tested": list(parse_qs(parsed.query).keys())
    }
