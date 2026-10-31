import sys
import time
import argparse
from voltrx.analyzer import TrafficLogAnalyzer
from voltrx.monitor import LiveTrafficMonitor
from voltrx.reporter import generate_html_report, export_json_report

BANNER = """
======================================================
  [#] VolTrx - Website Traffic & Access Log Analyzer
======================================================
"""

def print_summary_card(summary):
    print("\n" + "=" * 50)
    print(" [*] TRAFFIC OVERVIEW")
    print("=" * 50)
    print(f" Total Requests    : {summary['total_requests']:,}")
    print(f" Unique Visitors   : {summary['unique_visitors']:,}")
    print(f" Bandwidth Served  : {summary['total_bandwidth_mb']} MB")
    print(f" Security Alerts   : {summary['security_alerts_count']}")
    
    print("\n" + "-" * 50)
    print(" [*] HTTP STATUS CATEGORIES")
    print("-" * 50)
    for cat, count in summary["status_categories"].items():
        bar = "#" * min(30, int((count / (summary['total_requests'] or 1)) * 30))
        pct = (count / (summary['total_requests'] or 1)) * 100
        print(f" {cat:<20} : {count:>6} ({pct:>5.1f}%) | {bar}")

    print("\n" + "-" * 50)
    print(" [*] TOP 5 ENDPOINTS")
    print("-" * 50)
    for ep, count in summary["top_endpoints"][:5]:
        print(f" {count:>6} hits  ->  {ep}")

    print("\n" + "-" * 50)
    print(" [*] TOP 5 CLIENT IPs")
    print("-" * 50)
    for ip, count in summary["top_ips"][:5]:
        print(f" {count:>6} hits  ->  {ip}")

    if summary["security_alerts_count"] > 0:
        print("\n" + "!" * 50)
        print(" [!] DETECTED SUSPICIOUS REQUESTS")
        print("!" * 50)
        for a in summary["security_alerts"][:5]:
            print(f" [{a['type']}] from {a['ip']} -> {a['endpoint']}")
    print("=" * 50 + "\n")

def cmd_parse(args):
    print(f"[*] Analyzing log file: {args.logfile}...")
    analyzer = TrafficLogAnalyzer(args.logfile)
    summary = analyzer.parse()
    print_summary_card(summary)

    if args.html:
        generate_html_report(summary, args.html)
        print(f"[+] HTML Report generated: {args.html}")

    if args.json:
        export_json_report(summary, args.json)
        print(f"[+] JSON Report exported: {args.json}")

def cmd_monitor(args):
    print(f"[*] Monitoring live website traffic/health: {args.url}")
    print(f"[*] Sending {args.count} probes at {args.interval}s interval...\n")
    print(f"{'TIME':<10} {'STATUS':<8} {'LATENCY':<12} {'BYTES':<10} {'SERVER':<15}")
    print("-" * 60)

    monitor = LiveTrafficMonitor(args.url, interval=args.interval, timeout=args.timeout)
    for i in range(args.count):
        rec = monitor.probe()
        status_display = str(rec["status"])
        if rec["error"]:
            status_display += " (ERR)"
        print(f"{rec['timestamp']:<10} {status_display:<8} {rec['latency_ms']:>6.1f} ms    {rec['size_bytes']:>6} B   {rec['server']:<15}")
        if i < args.count - 1:
            time.sleep(args.interval)

    stats = monitor.get_stats()
    print("\n" + "=" * 50)
    print(f" [*] LIVE MONITORING SUMMARY for {args.url}")
    print("=" * 50)
    print(f" Total Probes    : {stats['total_probes']}")
    print(f" Uptime Rate     : {stats['uptime_percent']}%")
    print(f" Latency (Avg)   : {stats['avg_latency_ms']} ms")
    print(f" Latency (Min)   : {stats['min_latency_ms']} ms")
    print(f" Latency (Max)   : {stats['max_latency_ms']} ms")
    print("=" * 50 + "\n")

def create_sample_log(filename="sample_access.log"):
    logs = [
        '192.168.1.10 - - [25/Oct/2026:10:00:15 +0000] "GET / HTTP/1.1" 200 4521 "https://google.com" "Mozilla/5.0"',
        '192.168.1.12 - - [25/Oct/2026:10:01:20 +0000] "GET /api/products HTTP/1.1" 200 1205 "-" "Mozilla/5.0"',
        '192.168.1.15 - - [25/Oct/2026:10:02:40 +0000] "POST /api/login HTTP/1.1" 200 320 "-" "VolTrx-App/1.0"',
        '10.0.0.99 - - [25/Oct/2026:10:03:00 +0000] "GET /wp-admin/login.php HTTP/1.1" 404 182 "-" "BadBot/2.0"',
        '10.0.0.99 - - [25/Oct/2026:10:03:02 +0000] "GET /.env HTTP/1.1" 404 182 "-" "BadBot/2.0"',
        '10.0.0.99 - - [25/Oct/2026:10:03:05 +0000] "GET /../../etc/passwd HTTP/1.1" 403 160 "-" "BadBot/2.0"',
        '192.168.1.20 - - [25/Oct/2026:10:05:10 +0000] "GET /assets/style.css HTTP/1.1" 200 8400 "https://mywebsite.com" "Chrome/112.0"',
        '192.168.1.20 - - [25/Oct/2026:10:05:12 +0000] "GET /assets/script.js HTTP/1.1" 200 15200 "https://mywebsite.com" "Chrome/112.0"',
        '192.168.1.30 - - [25/Oct/2026:10:08:45 +0000] "GET /checkout HTTP/1.1" 500 512 "-" "Firefox/110.0"',
        '192.168.1.10 - - [25/Oct/2026:10:10:15 +0000] "GET /dashboard HTTP/1.1" 200 6210 "https://mywebsite.com" "Mozilla/5.0"',
    ]
    with open(filename, "w", encoding="utf-8") as f:
        f.write("\n".join(logs) + "\n")
    return filename

def cmd_demo(args):
    log_name = "sample_access.log"
    create_sample_log(log_name)
    print(f"[+] Sample access log generated: {log_name}")
    args.logfile = log_name
    args.html = "traffic_report.html"
    args.json = "traffic_report.json"
    cmd_parse(args)

def main():
    print(BANNER)
    parser = argparse.ArgumentParser(description="VolTrx - Website Traffic & Access Log Analyzer")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # parse
    p_parse = subparsers.add_parser("parse", help="Analyze web server access log (Apache/Nginx)")
    p_parse.add_argument("logfile", help="Path to access.log file")
    p_parse.add_argument("--html", help="Path to export HTML visual report", default=None)
    p_parse.add_argument("--json", help="Path to export JSON statistics", default=None)

    # monitor
    p_mon = subparsers.add_parser("monitor", help="Live website traffic and endpoint monitor")
    p_mon.add_argument("url", help="Target website URL (e.g. https://example.com)")
    p_mon.add_argument("--count", type=int, default=5, help="Number of probes to send (default: 5)")
    p_mon.add_argument("--interval", type=float, default=1.0, help="Interval in seconds (default: 1.0)")
    p_mon.add_argument("--timeout", type=float, default=5.0, help="Request timeout in seconds")

    # demo
    subparsers.add_parser("demo", help="Generate sample logs and run a live demo")

    args = parser.parse_args()
    if args.command == "parse":
        cmd_parse(args)
    elif args.command == "monitor":
        cmd_monitor(args)
    elif args.command == "demo":
        cmd_demo(args)
    else:
        parser.print_help()
