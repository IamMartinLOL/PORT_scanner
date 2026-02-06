# 🔎 Port Scanner & Vulnerability Reporter

A multithreaded **Python port scanner** with **banner grabbing**, basic **service detection**, and a simple **vulnerability lookup system** that generates a clean HTML report.

---

##  Features

* Scans ports **1–1024** by default
* Option to scan a **single port**
* Detects common services (FTP, SSH, HTTP, HTTPS, SMB, etc.)
* Performs **banner grabbing** to identify service versions
* Parses banners for:

  * Apache
  * Nginx
  * OpenSSH
* Checks discovered versions against a local **CVE database**
* Generates a styled **HTML vulnerability report**
* Uses **multithreading** for fast scanning

---

## 🛠 Requirements

* Python **3.8+**
* No external dependencies (standard library only)

---

## 🚀 Usage

### Scan all default ports (1–1024)

```bash
python scanner.py --target 192.168.1.10
```
You can also just use --t (instead of --target)

### Scan a specific port

```bash
python scanner.py --target 192.168.1.10 -p 22
```

---

##  Output

### Console Output

Displays open ports, detected services, banners, and vulnerabilities:

```
[OPEN] 22    SSH        OpenSSH_8.2p1 Ubuntu-4ubuntu0.5
   [VULN] openssh 8.2 → CVE-2021-41617

[OPEN] 80    HTTP       Apache/2.4.49 (Ubuntu)
   [VULN] apache 2.4.49 → CVE-2021-41773
```

---

### HTML Report

After the scan completes, a file is generated:

```
report.html
```

The report includes:

* Port number
* Service name
* Banner
* Vulnerability status
* CVE reference

Vulnerable services are highlighted in **red**, safe ones in **green**.

---

## 🧠 Vulnerability Database

The scanner uses a local JSON file:

```
vuln_db.json
```

### Example structure:

```json
{
    "apache": {
        "2.4.49": { "cve": "CVE-2021-41773" },
        "2.4.50": { "cve": "CVE-2021-42013" }
    },
    "nginx": {
        "1.18.0": { "cve": "CVE-2021-23017" }
    },
    "openssh": {
        "8.2": { "cve": "CVE-2021-41617" }
    }
}
```

If the file is missing, the scanner will still run but won’t report vulnerabilities.

---

## ⚙️ Configuration

You can modify:

| Variable  | Description        | Default  |
| --------- | ------------------ | -------- |
| `PORTS`   | Port range to scan | `1–1024` |
| `TIMEOUT` | Socket timeout     | `0.5s`   |
| `THREADS` | Number of threads  | `100`    |

---

## 🧩 Technologies Used

* `socket` — TCP connections
* `concurrent.futures` — multithreading
* `re` — banner parsing
* `json` — vulnerability database
* `argparse` — CLI arguments
* HTML/CSS — report generation

---

## !! Legal Disclaimer

This tool is intended **for educational purposes and authorized security testing only**.

Do **not** scan networks or systems without explicit permission. Unauthorized scanning may be illegal in your jurisdiction.

---

## 📌 Example Workflow

1. Run the scanner:

   ```bash
   python scanner.py --target ip
   ```

2. Wait for scan completion.

3. Open the generated report:

   ```bash
   report.html
   ```

---

## 📜 License

MIT License — free to use, modify, and distribute.

---

## 👨‍💻 Author

Created by IamMartinLOL. As a first cybersecurity project :)
