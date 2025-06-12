# 🔍 Checkmarx One - SCA Report Exporter

This Python script automates the generation and export of SCA (Software Composition Analysis) reports for projects in Checkmarx One. Reports are generated in multiple formats (CycloneDX, SPDX, JSON, PDF, etc.) and organized by project and application.

---

## 🛠 Prerequisites

- Python 3.7+
- An active Checkmarx One tenant
- Your **Refresh Token** (from Checkmarx One)
- Access to the **Checkmarx One API**
- Internet connectivity

---

## 🔐 Environment Variables

You must define the following environment variables before running the script:
Edit the below values in the script from Line number 9-14

| Variable Name         | Description                                                                                     |
|----------------------|-------------------------------------------------------------------------------------------------|
| `CX_REFRESH_TOKEN`    | 🔑 Your Checkmarx refresh token used to obtain an access token.                                 |
| `CX_TENANT`           | 🏢 Your tenant name (e.g., `mycompany`) for authentication URL.                                 |
| `FILE_FORMATS`        | 📦 Comma-separated report formats (e.g., `SpdxJson,CycloneDxJson,ScanReportPdf`)                |
| `INCLUDED_APPLICATIONS` | (Optional) 🔍 Comma-separated list of **Application Names** or **Application IDs** to filter projects. Leave empty to fetch all projects no matter which application. |


---

## 📥 Installation

1. Save the script file locally.
2. Install dependencies (if not already installed):

```bash
pip install requests
```

---

## ▶️ Running the Script

```bash
python sca_export_report.py
```

---

## 📤 Output

- The script will generate one or more files per project in the desired formats.
- File naming follows this structure:

```
<AppID>-<ProjectName>-<SBOMVersion>-<Timestamp>-<SBOMFormat>.extension
```

Example:

```
App_ID1-Project_test-2.2-13_06_2025-CycloneDx.json
```

- A summary CSV file named `sca_export_reports.csv` will also be created listing:
  - Project Name
  - Project ID
  - Application Name
  - Last SCA Scan ID
  - Format
  - Export ID

---

## 📦 Supported File Formats

You can choose one or multiple formats from this list (comma-separated):

| Format Name               | Description                      | Output Extension |
|--------------------------|----------------------------------|------------------|
| `CycloneDxJson`          | CycloneDX SBOM (JSON)            | `.json`          |
| `CycloneDxXml`           | CycloneDX SBOM (XML)             | `.xml`           |
| `SpdxJson`               | SPDX SBOM (JSON)                 | `.json`          |
| `RemediatedPackagesJson`| JSON of remediated packages      | `.json`          |
| `ScanReportJson`         | Standard scan report (JSON)      | `.json`          |
| `ScanReportXml`          | Standard scan report (XML)       | `.xml`           |
| `ScanReportCsv`          | Zipped CSV report                | `.zip`           |
| `ScanReportPdf`          | PDF scan report                  | `.pdf`           |

---

## ❗ Notes

- The script automatically handles pagination while fetching projects.
- Projects without a valid SCA scan will be skipped with a message.
- Retry logic is built in to wait for report generation (default 10 retries with 40 seconds delay).

---

## 🧑‍💻 Author

Bulusu Abhishek Murthy  
[Checkmarx](https://www.checkmarx.com)

---
