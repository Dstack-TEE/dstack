#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2024-2025 Phala Network <dstack@phala.network>
#
# SPDX-License-Identifier: Apache-2.0

"""
Mock Cloudflare DNS API Server

A mock server that simulates Cloudflare's DNS API for testing purposes.
Supports the following endpoints used by certbot:
- POST /client/v4/zones/{zone_id}/dns_records - Create DNS record
- GET /client/v4/zones/{zone_id}/dns_records - List DNS records
- DELETE /client/v4/zones/{zone_id}/dns_records/{record_id} - Delete DNS record
"""

import os
import uuid
import time
import json
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string
from functools import wraps

app = Flask(__name__)

# In-memory storage for DNS records
# Structure: {zone_id: {record_id: record_data}}
dns_records = {}

# Request/Response logs for debugging
request_logs = []
MAX_LOGS = 100

# Valid API tokens (for testing, accept any non-empty token or use env var)
VALID_TOKENS = os.environ.get("CF_API_TOKENS", "").split(",") if os.environ.get("CF_API_TOKENS") else None


def log_request(zone_id, method, path, req_data, resp_data, status_code):
    """Log API requests for the management UI."""
    log_entry = {
        "timestamp": datetime.now().isoformat(),
        "zone_id": zone_id,
        "method": method,
        "path": path,
        "request": req_data,
        "response": resp_data,
        "status_code": status_code,
    }
    request_logs.insert(0, log_entry)
    if len(request_logs) > MAX_LOGS:
        request_logs.pop()


def generate_record_id():
    """Generate a Cloudflare-style record ID."""
    return uuid.uuid4().hex[:32]


def get_current_time():
    """Get current time in Cloudflare format."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000000Z")


def verify_auth(f):
    """Decorator to verify Bearer token authentication."""
    @wraps(f)
    def decorated(*args, **kwargs):
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.startswith("Bearer "):
            return jsonify({
                "success": False,
                "errors": [{"code": 10000, "message": "Authentication error"}],
                "messages": [],
                "result": None
            }), 401

        token = auth_header[7:]  # Remove "Bearer " prefix

        # If VALID_TOKENS is set, validate against it; otherwise accept any token
        if VALID_TOKENS and token not in VALID_TOKENS:
            return jsonify({
                "success": False,
                "errors": [{"code": 10000, "message": "Invalid API token"}],
                "messages": [],
                "result": None
            }), 403

        return f(*args, **kwargs)
    return decorated


def cf_response(result, success=True, errors=None, messages=None):
    """Create a Cloudflare-style API response."""
    return {
        "success": success,
        "errors": errors or [],
        "messages": messages or [],
        "result": result
    }


def cf_error(message, code=1000):
    """Create a Cloudflare-style error response."""
    return cf_response(None, success=False, errors=[{"code": code, "message": message}])


# ==================== DNS Record Endpoints ====================

@app.route("/client/v4/zones/<zone_id>/dns_records", methods=["POST"])
@verify_auth
def create_dns_record(zone_id):
    """Create a new DNS record."""
    data = request.get_json()

    if not data:
        resp = cf_error("Invalid request body")
        log_request(zone_id, "POST", f"/zones/{zone_id}/dns_records", None, resp, 400)
        return jsonify(resp), 400

    record_type = data.get("type")
    name = data.get("name")

    if not record_type or not name:
        resp = cf_error("Missing required fields: type, name")
        log_request(zone_id, "POST", f"/zones/{zone_id}/dns_records", data, resp, 400)
        return jsonify(resp), 400

    # Initialize zone if not exists
    if zone_id not in dns_records:
        dns_records[zone_id] = {}

    record_id = generate_record_id()
    now = get_current_time()

    # Build record based on type
    record = {
        "id": record_id,
        "zone_id": zone_id,
        "zone_name": f"zone-{zone_id[:8]}.example.com",
        "name": name,
        "type": record_type,
        "ttl": data.get("ttl", 1),
        "proxied": data.get("proxied", False),
        "proxiable": False,
        "locked": False,
        "created_on": now,
        "modified_on": now,
        "meta": {
            "auto_added": False,
            "managed_by_apps": False,
            "managed_by_argo_tunnel": False
        }
    }

    # Handle different record types
    if record_type == "TXT":
        record["content"] = data.get("content", "")
    elif record_type == "CAA":
        caa_data = data.get("data", {})
        record["data"] = caa_data
        # Format content as Cloudflare does
        flags = caa_data.get("flags", 0)
        tag = caa_data.get("tag", "")
        value = caa_data.get("value", "")
        record["content"] = f'{flags} {tag} "{value}"'
    elif record_type == "A":
        record["content"] = data.get("content", "")
    elif record_type == "AAAA":
        record["content"] = data.get("content", "")
    elif record_type == "CNAME":
        record["content"] = data.get("content", "")
    else:
        record["content"] = data.get("content", "")

    dns_records[zone_id][record_id] = record

    resp = cf_response(record)
    log_request(zone_id, "POST", f"/zones/{zone_id}/dns_records", data, resp, 200)

    print(f"[CREATE] Zone: {zone_id}, Record: {record_id}, Type: {record_type}, Name: {name}")

    return jsonify(resp), 200


@app.route("/client/v4/zones/<zone_id>/dns_records", methods=["GET"])
@verify_auth
def list_dns_records(zone_id):
    """List DNS records for a zone."""
    zone_records = dns_records.get(zone_id, {})
    records_list = list(zone_records.values())

    # Filter by type if specified
    record_type = request.args.get("type")
    if record_type:
        records_list = [r for r in records_list if r["type"] == record_type]

    # Filter by name if specified
    name = request.args.get("name")
    if name:
        records_list = [r for r in records_list if r["name"] == name]

    resp = cf_response(records_list)
    log_request(zone_id, "GET", f"/zones/{zone_id}/dns_records", dict(request.args), resp, 200)

    return jsonify(resp), 200


@app.route("/client/v4/zones/<zone_id>/dns_records/<record_id>", methods=["GET"])
@verify_auth
def get_dns_record(zone_id, record_id):
    """Get a specific DNS record."""
    zone_records = dns_records.get(zone_id, {})
    record = zone_records.get(record_id)

    if not record:
        resp = cf_error("Record not found", 81044)
        log_request(zone_id, "GET", f"/zones/{zone_id}/dns_records/{record_id}", None, resp, 404)
        return jsonify(resp), 404

    resp = cf_response(record)
    log_request(zone_id, "GET", f"/zones/{zone_id}/dns_records/{record_id}", None, resp, 200)

    return jsonify(resp), 200


@app.route("/client/v4/zones/<zone_id>/dns_records/<record_id>", methods=["PUT"])
@verify_auth
def update_dns_record(zone_id, record_id):
    """Update a DNS record."""
    zone_records = dns_records.get(zone_id, {})
    record = zone_records.get(record_id)

    if not record:
        resp = cf_error("Record not found", 81044)
        log_request(zone_id, "PUT", f"/zones/{zone_id}/dns_records/{record_id}", None, resp, 404)
        return jsonify(resp), 404

    data = request.get_json()
    if not data:
        resp = cf_error("Invalid request body")
        log_request(zone_id, "PUT", f"/zones/{zone_id}/dns_records/{record_id}", None, resp, 400)
        return jsonify(resp), 400

    # Update allowed fields
    for field in ["name", "type", "content", "ttl", "proxied", "data"]:
        if field in data:
            record[field] = data[field]

    record["modified_on"] = get_current_time()

    resp = cf_response(record)
    log_request(zone_id, "PUT", f"/zones/{zone_id}/dns_records/{record_id}", data, resp, 200)

    print(f"[UPDATE] Zone: {zone_id}, Record: {record_id}")

    return jsonify(resp), 200


@app.route("/client/v4/zones/<zone_id>/dns_records/<record_id>", methods=["DELETE"])
@verify_auth
def delete_dns_record(zone_id, record_id):
    """Delete a DNS record."""
    zone_records = dns_records.get(zone_id, {})

    if record_id not in zone_records:
        resp = cf_error("Record not found", 81044)
        log_request(zone_id, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}", None, resp, 404)
        return jsonify(resp), 404

    del zone_records[record_id]

    resp = cf_response({"id": record_id})
    log_request(zone_id, "DELETE", f"/zones/{zone_id}/dns_records/{record_id}", None, resp, 200)

    print(f"[DELETE] Zone: {zone_id}, Record: {record_id}")

    return jsonify(resp), 200


# ==================== Zone Endpoints (for completeness) ====================

@app.route("/client/v4/zones/<zone_id>", methods=["GET"])
@verify_auth
def get_zone(zone_id):
    """Get zone details (mock)."""
    zone = {
        "id": zone_id,
        "name": f"zone-{zone_id[:8]}.example.com",
        "status": "active",
        "paused": False,
        "type": "full",
        "development_mode": 0,
        "name_servers": [
            "ns1.mock-cloudflare.com",
            "ns2.mock-cloudflare.com"
        ],
        "created_on": "2024-01-01T00:00:00.000000Z",
        "modified_on": get_current_time(),
    }

    resp = cf_response(zone)
    log_request(zone_id, "GET", f"/zones/{zone_id}", None, resp, 200)

    return jsonify(resp), 200


# ==================== Management UI ====================

MANAGEMENT_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mock Cloudflare DNS API - Management</title>
    <style>
        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: #1a1a2e;
            color: #eaeaea;
            min-height: 100vh;
        }
        .container {
            max-width: 1400px;
            margin: 0 auto;
            padding: 20px;
        }
        header {
            background: linear-gradient(135deg, #f6821f 0%, #faad3f 100%);
            padding: 20px;
            margin-bottom: 20px;
            border-radius: 8px;
        }
        header h1 {
            color: #1a1a2e;
            font-size: 1.5em;
        }
        header p {
            color: #333;
            margin-top: 5px;
        }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: #25274d;
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }
        .stat-card h3 {
            font-size: 2em;
            color: #f6821f;
        }
        .stat-card p {
            color: #888;
            margin-top: 5px;
        }
        .section {
            background: #25274d;
            border-radius: 8px;
            margin-bottom: 20px;
            overflow: hidden;
        }
        .section-header {
            background: #2e3156;
            padding: 15px 20px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .section-header h2 {
            font-size: 1.1em;
        }
        .section-content {
            padding: 20px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #3a3d6b;
        }
        th {
            background: #2e3156;
            font-weight: 600;
        }
        tr:hover {
            background: #2e3156;
        }
        .record-type {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .record-type.TXT { background: #3b82f6; }
        .record-type.CAA { background: #8b5cf6; }
        .record-type.A { background: #10b981; }
        .record-type.AAAA { background: #06b6d4; }
        .record-type.CNAME { background: #f59e0b; }
        .method {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85em;
            font-weight: 600;
        }
        .method.GET { background: #10b981; }
        .method.POST { background: #3b82f6; }
        .method.PUT { background: #f59e0b; }
        .method.DELETE { background: #ef4444; }
        .btn {
            background: #f6821f;
            color: #1a1a2e;
            border: none;
            padding: 8px 16px;
            border-radius: 4px;
            cursor: pointer;
            font-weight: 600;
        }
        .btn:hover {
            background: #faad3f;
        }
        .btn-danger {
            background: #ef4444;
            color: white;
        }
        .btn-danger:hover {
            background: #dc2626;
        }
        .content-preview {
            max-width: 300px;
            overflow: hidden;
            text-overflow: ellipsis;
            white-space: nowrap;
            font-family: monospace;
            font-size: 0.9em;
        }
        .log-entry {
            background: #1a1a2e;
            border-radius: 4px;
            padding: 10px;
            margin-bottom: 10px;
            font-family: monospace;
            font-size: 0.85em;
        }
        .log-time {
            color: #888;
        }
        .empty-state {
            text-align: center;
            padding: 40px;
            color: #666;
        }
        .tabs {
            display: flex;
            border-bottom: 1px solid #3a3d6b;
            margin-bottom: 15px;
        }
        .tab {
            padding: 10px 20px;
            cursor: pointer;
            border-bottom: 2px solid transparent;
        }
        .tab.active {
            border-bottom-color: #f6821f;
            color: #f6821f;
        }
        .tab-content {
            display: none;
        }
        .tab-content.active {
            display: block;
        }
        pre {
            background: #1a1a2e;
            padding: 10px;
            border-radius: 4px;
            overflow-x: auto;
            font-size: 0.85em;
        }
        .refresh-btn {
            position: fixed;
            bottom: 20px;
            right: 20px;
            width: 50px;
            height: 50px;
            border-radius: 50%;
            font-size: 1.5em;
            display: flex;
            align-items: center;
            justify-content: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Mock Cloudflare DNS API</h1>
            <p>Testing server for ACME DNS-01 challenges</p>
        </header>

        <div class="stats">
            <div class="stat-card">
                <h3 id="zone-count">{{ zone_count }}</h3>
                <p>Zones</p>
            </div>
            <div class="stat-card">
                <h3 id="record-count">{{ record_count }}</h3>
                <p>DNS Records</p>
            </div>
            <div class="stat-card">
                <h3 id="request-count">{{ request_count }}</h3>
                <p>API Requests</p>
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>DNS Records</h2>
                <button class="btn btn-danger" onclick="clearAllRecords()">Clear All</button>
            </div>
            <div class="section-content">
                {% if records %}
                <table>
                    <thead>
                        <tr>
                            <th>Zone ID</th>
                            <th>Type</th>
                            <th>Name</th>
                            <th>Content</th>
                            <th>Created</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for record in records %}
                        <tr>
                            <td><code>{{ record.zone_id[:12] }}...</code></td>
                            <td><span class="record-type {{ record.type }}">{{ record.type }}</span></td>
                            <td>{{ record.name }}</td>
                            <td class="content-preview" title="{{ record.content }}">{{ record.content }}</td>
                            <td>{{ record.created_on[:19] }}</td>
                            <td>
                                <button class="btn btn-danger" onclick="deleteRecord('{{ record.zone_id }}', '{{ record.id }}')">Delete</button>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
                {% else %}
                <div class="empty-state">
                    <p>No DNS records yet. Records created via API will appear here.</p>
                </div>
                {% endif %}
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>Recent API Requests</h2>
                <button class="btn" onclick="clearLogs()">Clear Logs</button>
            </div>
            <div class="section-content">
                {% if logs %}
                {% for log in logs %}
                <div class="log-entry">
                    <span class="log-time">{{ log.timestamp }}</span>
                    <span class="method {{ log.method }}">{{ log.method }}</span>
                    <span>{{ log.path }}</span>
                    <span style="color: {% if log.status_code == 200 %}#10b981{% else %}#ef4444{% endif %}">
                        ({{ log.status_code }})
                    </span>
                    {% if log.request %}
                    <details>
                        <summary>Request/Response</summary>
                        <pre>Request: {{ log.request | tojson(indent=2) }}</pre>
                        <pre>Response: {{ log.response | tojson(indent=2) }}</pre>
                    </details>
                    {% endif %}
                </div>
                {% endfor %}
                {% else %}
                <div class="empty-state">
                    <p>No API requests yet.</p>
                </div>
                {% endif %}
            </div>
        </div>

        <div class="section">
            <div class="section-header">
                <h2>API Usage</h2>
            </div>
            <div class="section-content">
                <p style="margin-bottom: 15px;">Base URL: <code id="base-url"></code></p>
                <pre id="api-examples"></pre>
            </div>
        </div>
    </div>

    <button class="btn refresh-btn" onclick="location.reload()">&#x21bb;</button>

    <script>
        function deleteRecord(zoneId, recordId) {
            if (!confirm('Delete this record?')) return;
            fetch(`/api/records/${zoneId}/${recordId}`, { method: 'DELETE' })
                .then(() => location.reload());
        }

        function clearAllRecords() {
            if (!confirm('Clear all DNS records?')) return;
            fetch('/api/records', { method: 'DELETE' })
                .then(() => location.reload());
        }

        function clearLogs() {
            fetch('/api/logs', { method: 'DELETE' })
                .then(() => location.reload());
        }

        // Auto-refresh every 5 seconds
        setTimeout(() => location.reload(), 5000);

        // Set API base URL from browser location
        const baseUrl = window.location.origin + '/client/v4';
        document.getElementById('base-url').textContent = baseUrl;
        document.getElementById('api-examples').textContent = `# Create TXT record
curl -X POST "${baseUrl}/zones/YOUR_ZONE_ID/dns_records" \\
     -H "Authorization: Bearer YOUR_API_TOKEN" \\
     -H "Content-Type: application/json" \\
     --data '{"type":"TXT","name":"_acme-challenge.example.com","content":"test-value"}'

# List records
curl -X GET "${baseUrl}/zones/YOUR_ZONE_ID/dns_records" \\
     -H "Authorization: Bearer YOUR_API_TOKEN"

# Delete record
curl -X DELETE "${baseUrl}/zones/YOUR_ZONE_ID/dns_records/RECORD_ID" \\
     -H "Authorization: Bearer YOUR_API_TOKEN"`;
    </script>
</body>
</html>
"""


@app.route("/")
def management_ui():
    """Render the management UI."""
    all_records = []
    for zone_id, records in dns_records.items():
        all_records.extend(records.values())

    # Sort by created time, newest first
    all_records.sort(key=lambda r: r.get("created_on", ""), reverse=True)

    return render_template_string(
        MANAGEMENT_HTML,
        zone_count=len(dns_records),
        record_count=sum(len(r) for r in dns_records.values()),
        request_count=len(request_logs),
        records=all_records,
        logs=request_logs[:20],
        port=os.environ.get("PORT", 8080)
    )


# ==================== Management API ====================

@app.route("/api/records", methods=["DELETE"])
def clear_all_records():
    """Clear all DNS records."""
    dns_records.clear()
    return jsonify({"success": True})


@app.route("/api/records/<zone_id>/<record_id>", methods=["DELETE"])
def delete_record_ui(zone_id, record_id):
    """Delete a specific record from UI."""
    if zone_id in dns_records and record_id in dns_records[zone_id]:
        del dns_records[zone_id][record_id]
    return jsonify({"success": True})


@app.route("/api/logs", methods=["DELETE"])
def clear_logs():
    """Clear request logs."""
    request_logs.clear()
    return jsonify({"success": True})


@app.route("/api/records", methods=["GET"])
def get_all_records():
    """Get all records as JSON."""
    all_records = []
    for zone_id, records in dns_records.items():
        all_records.extend(records.values())
    return jsonify(all_records)


@app.route("/health")
def health():
    """Health check endpoint."""
    return jsonify({"status": "healthy", "records": sum(len(r) for r in dns_records.values())})


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 8080))
    debug = os.environ.get("DEBUG", "false").lower() == "true"

    print(f"""
    ╔═══════════════════════════════════════════════════════════════╗
    ║         Mock Cloudflare DNS API Server                        ║
    ╠═══════════════════════════════════════════════════════════════╣
    ║  Management UI:  http://localhost:{port}/                         ║
    ║  API Base URL:   http://localhost:{port}/client/v4                ║
    ╚═══════════════════════════════════════════════════════════════╝
    """)

    app.run(host="0.0.0.0", port=port, debug=debug)
