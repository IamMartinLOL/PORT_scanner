import argparse
import json
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from tqdm import tqdm

PORTS = range(1, 1025)
TIMEOUT = 0.5
THREADS = 100

COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "TELNET",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    135: "MS RPC",
    139: "NetBIOS",
    443: "HTTPS",
    445: "SMB",
}

COMMON_PATHS = [
    "/admin",
    "/login",
    "/dashboard",
    "/backup",
    "/.git",
    "/.env",
    "/config.php",
    "/phpinfo.php",
    "/server-status",
    "/report.html",
]

results = []


def web_vuln_scan(target, port):

    tqdm.write("\n[+] Starting web vulnerability scan")

    protocol = "https" if port == 443 else "http"

    for path in COMMON_PATHS:
        url = f"{protocol}://{target}{path}"

        try:
            r = requests.get(url, timeout=3, verify=False)

            if r.status_code == 200:
                tqdm.write(f"[FOUND] {url}")

            elif r.status_code == 403:
                tqdm.write(f"[FORBIDDEN] {url}")

        except requests.RequestException:
            pass


def generate_html_report(results, target):

    html = f"""
    <html>
    <head>
        <title>Scan Report - {target}</title>
        <style>
            body {{
                font-family: Arial;
                background: #0f172a;
                color: white;
            }}
            table {{
                border-collapse: collapse;
                width: 100%;
            }}
            th, td {{
                border: 1px solid #334155;
                padding: 8px;
            }}
            th {{
                background: #1e293b;
            }}
            .vuln {{ color: red; font-weight: bold; }}
            .ok {{ color: lightgreen; }}
        </style>
    </head>
    <body>

    <h1>Vulnerability Scan Report</h1>
    <h3>Target: {target}</h3>

    <table>
        <tr>
            <th>Port</th>
            <th>Service</th>
            <th>Banner</th>
            <th>OS</th>
            <th>Status</th>
            <th>CVE</th>
        </tr>
    """

    for r in results:
        if r["vuln"]:
            status = '<span class="vuln">VULNERABLE</span>'
            cve = r["vuln"]["cve"]
        else:
            status = '<span class="ok">OK</span>'
            cve = "-"

        html += f"""
        <tr>
            <td>{r["port"]}</td>
            <td>{r["service"]}</td>
            <td>{r["banner"]}</td>
            <td>{r["os"]}</td>
            <td>{status}</td>
            <td>{cve}</td>
        </tr>
        """

    html += "</table></body></html>"

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("\n[+] HTML report saved → report.html")


def grab_banner(sock):
    try:
        sock.settimeout(TIMEOUT)
        data = sock.recv(1024)
        if data:
            return data.decode(errors="ignore").splitlines()[0].strip()
    except:
        pass

    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
        if data:
            return data.decode(errors="ignore").splitlines()[0].strip()
    except:
        pass

    return ""


def parse_service(banner):

    patterns = {
        "apache": r"Apache/?([\d\.]+)",
        "nginx": r"nginx/?([\d\.]+)",
        "openssh": r"OpenSSH[_ ]([\d\.]+)",
    }

    for service, pattern in patterns.items():
        match = re.search(pattern, banner, re.I)
        if match:
            return service, match.group(1)

    return None, None


def detect_os(banner):

    patterns = {
        "Linux": r"ubuntu|debian|centos|linux",
        "Windows": r"microsoft|iis|windows",
        "FreeBSD": r"freebsd",
        "Unix": r"unix",
    }

    for os, pattern in patterns.items():
        if re.search(pattern, banner, re.I):
            return os

    return "Unknown"


try:
    with open("vuln_db.json") as f:
        VULN_DB = json.load(f)
except FileNotFoundError:
    VULN_DB = {}


def check_vuln(service, version):
    if service in VULN_DB:
        if version in VULN_DB[service]:
            return VULN_DB[service][version]
    return None


def scan_port(target, port):

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((target, port))

            if result == 0:
                banner = grab_banner(s)
                service_name = COMMON_SERVICES.get(port, "Unknown")

                parsed_service, version = parse_service(banner)
                os_guess = detect_os(banner)

                vuln = None
                if parsed_service:
                    vuln = check_vuln(parsed_service, version)

                results.append(
                    {
                        "port": port,
                        "service": service_name,
                        "banner": banner,
                        "os": os_guess,
                        "vuln": vuln,
                    }
                )

                tqdm.write(f"[OPEN] {port:<5} {service_name:<10} {banner}")

                if vuln:
                    tqdm.write(f"   [VULN] {parsed_service} {version} → {vuln['cve']}")

                if port in [80, 443]:
                    web_vuln_scan(target, port)

    except OSError:
        pass


def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-t", required=True)

    args = parser.parse_args()
    target = args.target

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        futures = [executor.submit(scan_port, target, port) for port in PORTS]

        for future in tqdm(
            as_completed(futures), total=len(futures), desc="Scanning ports"
        ):
            future.result()

    print("\nScan completed.")

    generate_html_report(results, target)


if __name__ == "__main__":
    main()
