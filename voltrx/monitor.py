import time
import urllib.request
import urllib.error
import ssl
import socket
from urllib.parse import urlparse
from collections import deque

class LiveTrafficMonitor:
    def __init__(self, target_url, interval=2.0, timeout=10.0):
        if not target_url.startswith(("http://", "https://")):
            target_url = "https://" + target_url
        self.target_url = target_url
        self.interval = interval
        self.timeout = timeout

        self.history = deque(maxlen=100)
        self.latencies = []
        self.status_counts = {}
        self.running = False

    def probe(self):
        """Perform a single traffic probe and measure latency/headers."""
        start_time = time.perf_counter()
        parsed = urlparse(self.target_url)
        
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        req = urllib.request.Request(
            self.target_url,
            headers={
                "User-Agent": "VolTrx-TrafficMonitor/1.0 (+https://github.com/BenSnn/VolTrx)",
                "Accept": "*/*"
            }
        )

        status_code = None
        error_msg = None
        content_size = 0
        server_header = "-"
        cache_control = "-"

        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=ctx) as resp:
                elapsed_ms = (time.perf_counter() - start_time) * 1000.0
                status_code = resp.status
                headers = dict(resp.headers)
                content = resp.read(1024 * 1024)
                content_size = len(content)
                server_header = headers.get("Server", headers.get("server", "-"))
                cache_control = headers.get("Cache-Control", headers.get("cache-control", "-"))
        except urllib.error.HTTPError as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            status_code = e.code
            error_msg = str(e)
        except Exception as e:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            status_code = 0
            error_msg = str(e)

        self.latencies.append(elapsed_ms)
        self.status_counts[status_code] = self.status_counts.get(status_code, 0) + 1

        record = {
            "timestamp": time.strftime("%H:%M:%S"),
            "url": self.target_url,
            "status": status_code,
            "latency_ms": round(elapsed_ms, 2),
            "size_bytes": content_size,
            "server": server_header,
            "cache": cache_control,
            "error": error_msg
        }
        self.history.append(record)
        return record

    def get_stats(self):
        total_pings = len(self.latencies)
        if total_pings == 0:
            return {}

        success_count = sum(1 for s in self.history if 200 <= s["status"] < 400)
        uptime_pct = round((success_count / total_pings) * 100, 2)
        avg_lat = round(sum(self.latencies) / total_pings, 2)
        min_lat = round(min(self.latencies), 2)
        max_lat = round(max(self.latencies), 2)

        return {
            "target": self.target_url,
            "total_probes": total_pings,
            "uptime_percent": uptime_pct,
            "avg_latency_ms": avg_lat,
            "min_latency_ms": min_lat,
            "max_latency_ms": max_lat,
            "status_distribution": self.status_counts
        }
