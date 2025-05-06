# Security-Scripts

Welcome to my cybersecurity automation portfolio. This repository showcases a curated collection of scripts I've developed to automate common security tasks across vulnerability management, endpoint deployment, and firewall analysis.

These scripts demonstrate practical experience using Python, PowerShell, and Bash in real-world security operations.

---

## 🔧 What's Inside

All scripts are stored in the `scripts/` directory:

| Script                         | Language   | Description                                                                                                          |
| ------------------------------ | ---------- | -------------------------------------------------------------------------------------------------------------------- |
| `cve_query.py`                 | Python     | Queries Tenable Security Center for CVE-related data, extracts plugin and asset info, and generates an Excel report. |
| `install_nessus_agent.sh`      | Bash       | Automates installation and registration of Nessus Agents on RHEL-based systems.                                      |
| `firewall_data_pull.py`        | Python     | Pulls and filters firewall IP address data for audit or cleanup purposes.                                            |
| `download_tenable_reports.ps1` | PowerShell | Downloads vulnerability reports from Tenable.sc for compliance and offline review.                                   |

<!-- Add more rows as you add more scripts -->

Each script is commented for clarity and sanitized for public review.

---

## 🛡️ Key Features

* Tenable API integration (for CVEs, agents, reports)
* Secure credential handling using Fernet encryption
* Structured logging and error handling
* Excel output formatting with OpenPyXL
* Cross-platform scripting (Linux, Windows)

---

## 📂 Repository Structure

```
Security-Scripts/
├── README.md
├── LICENSE
└── scripts/
    ├── *.py
    ├── *.ps1
    └── *.sh
```

---

## 📝 License

This project is licensed under the [MIT License](LICENSE). Use it freely with attribution.

---

## 🤛🏾 About

I'm Corderius Shepherd, a security engineer with experience in vulnerability management, compliance automation, and security tooling. This repo serves as a public portfolio of practical work—feel free to explore the code or reach out with questions.
