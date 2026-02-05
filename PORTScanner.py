import socket
from concurrent.futures import ThreadPoolExecutor
import argparse
import re
import json

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
    445: "SMB"
}


results = []


# ----------------------------
# HTML report
# ----------------------------
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
            <td>{r['port']}</td>
            <td>{r['service']}</td>
            <td>{r['banner']}</td>
            <td>{status}</td>
            <td>{cve}</td>
        </tr>
        """

    html += "</table></body></html>"

    with open("report.html", "w", encoding="utf-8") as f:
        f.write(html)

    print("\n[+] HTML report saved → report.html")


# ----------------------------
# Banner grabbing
# ----------------------------
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


# ----------------------------
# Parsing
# ----------------------------
def parse_service(banner):
    patterns = {
        "apache": r"Apache/?([\d\.]+)",
        "nginx": r"nginx/?([\d\.]+)",
        "openssh": r"OpenSSH[_ ]([\d\.]+)"
    }

    for service, pattern in patterns.items():
        match = re.search(pattern, banner, re.I)
        if match:
            return service, match.group(1)

    return None, None


# ----------------------------
# Vuln DB
# ----------------------------
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


# ----------------------------
# Scan logic
# ----------------------------
def scan_port(target, port, single=False):

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((target, port))

            if result == 0:
                banner = grab_banner(s)
                service_name = COMMON_SERVICES.get(port, "Unknown")

                parsed_service, version = parse_service(banner)
                vuln = None

                if parsed_service:
                    vuln = check_vuln(parsed_service, version)


                results.append({
                    "port": port,
                    "service": service_name,
                    "banner": banner,
                    "vuln": vuln
                })

                print(f"[OPEN] {port:<5} {service_name:<10} {banner}")

                if vuln:
                    print(f"   [VULN] {parsed_service} {version} → {vuln['cve']}")

            else:
                if single:
                    print(f"[CLOSED] {port}")

    except OSError:
        pass


# ----------------------------
# Main
# ----------------------------
def main():

    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-t", required=True)
    parser.add_argument("-p", type=int)

    args = parser.parse_args()
    target = args.target

    with ThreadPoolExecutor(max_workers=THREADS) as executor:

        if args.p:
            executor.submit(scan_port, target, args.p, True)
        else:
            for port in PORTS:
                executor.submit(scan_port, target, port)

    print("\nScan completed.")

    generate_html_report(results, target)


if __name__ == "__main__":
    main()
