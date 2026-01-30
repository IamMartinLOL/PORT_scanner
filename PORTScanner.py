import socket
from concurrent.futures import ThreadPoolExecutor
import argparse

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

def grab_banner(sock):
    try:
        sock.settimeout(TIMEOUT)
        data = sock.recv(1024)
        if data:
            return data.decode(errors="ignore").splitlines()[0].strip()
    except (socket.timeout, OSError):
        pass


    try:
        sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
        data = sock.recv(1024)
        if data:
            return data.decode(errors="ignore").splitlines()[0].strip()
    except (socket.timeout, OSError):
        pass

    return ""

def scan_port(target, port, single=False):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(TIMEOUT)
            result = s.connect_ex((target, port))

            if result == 0:
                banner = grab_banner(s)
                service = COMMON_SERVICES.get(port, "Unknown")
                print(f"[OPEN] {port:<5} {service:<10} {banner}")
            else:
                if single:
                    print(f"[CLOSED] {port}")
    except OSError:
        pass


def main():
    parser = argparse.ArgumentParser(
        description="Jednoduchý port scanner (používej zodpovědně)"
    )
    parser.add_argument(
        "--target",
        required=True,
        help="cílová IP nebo hostname"
    )
    parser.add_argument(
        "-p",
        type=int,
        help="Port ke skenování (pokud není zadán, skenují se všechny)"
    )

    args = parser.parse_args()
    target = args.target

    if args.p:
        print(f"Scanning {target} on port {args.p}...\n")
    else:
        print(f"Scanning {target} on ports 1–1024...\n")

    with ThreadPoolExecutor(max_workers=THREADS) as executor:
        if args.p:
            executor.submit(scan_port, target, args.p, True)
        else:
            for port in PORTS:
                executor.submit(scan_port, target, port, False)

    print("\nScan completed.")

if __name__ == "__main__":
    main()
