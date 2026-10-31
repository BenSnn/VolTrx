import re
import os
from collections import Counter, defaultdict
from datetime import datetime

# Regex for Apache / Nginx Combined Log Format
# Format: $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
COMBINED_LOG_REGEX = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+"(?P<request>[^"]*)"\s+(?P<status>\d{3})\s+(?P<bytes>\S+)(?:\s+"(?P<referer>[^"]*)"\s+"(?P<agent>[^"]*)")?'
)

SUSPICIOUS_PATTERNS = [
    (re.compile(r'(\.\./|\.\.\\)', re.I), "Path Traversal Attempt"),
    (re.compile(r'(union\s+select|select.*from|<script|javascript:)', re.I), "XSS / SQLi Probe"),
    (re.compile(r'(\.env|\.git|wp-admin|phpmyadmin|\.config|\.aws)', re.I), "Sensitive File Scanning"),
    (re.compile(r'(/etc/passwd|cmd\.exe|powershell)', re.I), "Command Execution Probe"),
]

class TrafficLogAnalyzer:
    def __init__(self, log_file_path):
        self.log_file_path = log_file_path
        self.total_lines = 0
        self.parsed_lines = 0
        self.total_bytes = 0

        self.ips = Counter()
        self.status_codes = Counter()
        self.endpoints = Counter()
        self.methods = Counter()
        self.referers = Counter()
        self.user_agents = Counter()
        self.hourly_traffic = defaultdict(int)
        self.security_alerts = []

    def parse(self):
        if not os.path.exists(self.log_file_path):
            raise FileNotFoundError(f"Log file not found: {self.log_file_path}")

        with open(self.log_file_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                self.total_lines += 1
                match = COMBINED_LOG_REGEX.match(line.strip())
                if match:
                    self.parsed_lines += 1
                    data = match.groupdict()

                    ip = data["ip"]
                    status = int(data["status"])
                    request = data["request"]
                    bytes_sent = int(data["bytes"]) if data["bytes"].isdigit() else 0
                    time_str = data["time"]
                    referer = data.get("referer") or "-"
                    agent = data.get("agent") or "-"

                    self.ips[ip] += 1
                    self.status_codes[status] += 1
                    self.total_bytes += bytes_sent

                    req_parts = request.split()
                    if req_parts:
                        method = req_parts[0]
                        endpoint = req_parts[1] if len(req_parts) > 1 else "/"
                        self.methods[method] += 1
                        self.endpoints[endpoint] += 1

                        # Security checks
                        for pattern, threat_type in SUSPICIOUS_PATTERNS:
                            if pattern.search(endpoint):
                                self.security_alerts.append({
                                    "ip": ip,
                                    "time": time_str,
                                    "type": threat_type,
                                    "endpoint": endpoint
                                })

                    if referer != "-":
                        self.referers[referer] += 1

                    if agent != "-":
                        self.user_agents[agent] += 1

                    # Parse hour: e.g. 25/Oct/2026:14:32:10 +0000
                    try:
                        dt = datetime.strptime(time_str.split()[0], "%d/%b/%Y:%H:%M:%S")
                        hour_key = dt.strftime("%Y-%m-%d %H:00")
                        self.hourly_traffic[hour_key] += 1
                    except Exception:
                        pass

        return self.get_summary()

    def get_summary(self):
        unique_ips = len(self.ips)
        mb_transferred = round(self.total_bytes / (1024 * 1024), 2)
        
        status_categories = {
            "2xx (Success)": sum(count for code, count in self.status_codes.items() if 200 <= code < 300),
            "3xx (Redirect)": sum(count for code, count in self.status_codes.items() if 300 <= code < 400),
            "4xx (Client Error)": sum(count for code, count in self.status_codes.items() if 400 <= code < 500),
            "5xx (Server Error)": sum(count for code, count in self.status_codes.items() if 500 <= code < 600),
        }

        return {
            "total_requests": self.parsed_lines,
            "failed_parses": self.total_lines - self.parsed_lines,
            "unique_visitors": unique_ips,
            "total_bandwidth_mb": mb_transferred,
            "status_categories": status_categories,
            "status_codes": dict(self.status_codes.most_common(10)),
            "top_endpoints": self.endpoints.most_common(10),
            "top_ips": self.ips.most_common(10),
            "http_methods": dict(self.methods),
            "top_user_agents": self.user_agents.most_common(5),
            "top_referers": self.referers.most_common(5),
            "hourly_traffic": sorted(self.hourly_traffic.items()),
            "security_alerts_count": len(self.security_alerts),
            "security_alerts": self.security_alerts[:10]
        }
