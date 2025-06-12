import os
import requests
import time
import csv
import json
from datetime import datetime

# === Environment Variables ===
CX_REFRESH_TOKEN = os.getenv("CX_REFRESH_TOKEN","Enter Your API key") #Enter the API key
CX_TENANT = os.getenv("CX_TENANT", "Enter your Tenant Name") #Enter the Tenant Name
AUTH_URL = f"https://ind.iam.checkmarx.net/auth/realms/{CX_TENANT}/protocol/openid-connect/token" #Update the URL
API_BASE_URL = "https://ind.ast.checkmarx.net/api" #Update the URL
FILE_FORMATS = [fmt.strip() for fmt in os.getenv("FILE_FORMATS", "SpdxJson,CycloneDxJson").split(",") if fmt.strip()] #Update your file format as per requirement. You can either add any one format or multiple formats with comma seperation for example -  CycloneDxJson, CycloneDxXml, SpdxJson, RemediatedPackagesJson,ScanReportJson,ScanReportXml,ScanReportCsv,ScanReportPdf
INCLUDED_APPLICATIONS = os.getenv("INCLUDED_APPLICATIONS", "Enter your application name/HDFC app ID OR leave it empty if you want to get all the applications data").strip() #Example AppID1,APPID2,APPID3
# === Environment Variables ===
INCLUDED_APP_LIST = [app.strip().replace(" ", "_") for app in INCLUDED_APPLICATIONS.split(",") if app.strip()]
RETRIES = 10
DELAY = 40

def sanitize_filename(text):
    return "".join(c if c.isalnum() else "_" for c in text)

def get_current_timestamp():
    return datetime.now().strftime("%d_%m_%Y")

def get_access_token():
    print("🔐 Getting access token...")
    data = {
        "grant_type": "refresh_token",
        "client_id": "ast-app",
        "refresh_token": CX_REFRESH_TOKEN
    }
    response = requests.post(AUTH_URL, data=data)
    if response.status_code != 200:
        print(f"❌ Failed to get access token: {response.text}")
        return None
    print("✅ Access token retrieved.")
    return response.json().get("access_token")

def get_all_projects(headers):
    print("📦 Fetching all projects...")
    all_projects = []
    offset = 0
    limit = 1000
    seen_ids = set()

    while True:
        url = f"{API_BASE_URL}/projects?offset={offset}&limit={limit}"
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        data = res.json()
        projects = data.get("projects", [])
        total_count = data.get("totalCount", 0)

        new_projects = [p for p in projects if p["id"] not in seen_ids]
        for project in new_projects:
            seen_ids.add(project["id"])
        all_projects.extend(new_projects)

        offset += limit
        if offset >= total_count:
            break

    return all_projects

def get_last_sca_scan_id(project_id, headers):
    url = f"{API_BASE_URL}/projects/last-scan?project-ids={project_id}"
    try:
        res = requests.get(url, headers=headers)
        res.raise_for_status()
        data = res.json()
        scan_info = data.get(project_id)
        if scan_info and scan_info.get("id") and any("sca" in e.lower() for e in scan_info.get("engines", [])):
            return scan_info.get("id")
        else:
            print(f"⏩ {project_id}: No SCA scan was not run in the last latest scan.")
    except requests.exceptions.HTTPError as e:
        print(f"❌ Error retrieving last scan for {project_id}: {e}")
    return None

def get_application_map(headers):
    app_id_to_name = {}
    app_url = f"{API_BASE_URL}/applications"
    app_resp = requests.get(app_url, headers=headers)
    app_resp.raise_for_status()
    for app in app_resp.json().get("applications", []):
        app_id = app.get("id")
        app_name = app.get("name", "NoAppID").replace(" ", "_")
        if app_id:
            app_id_to_name[app_id] = app_name
    return app_id_to_name

def create_report(scan_id, headers, file_format):
    payload = {
        "scanId": scan_id,
        "fileFormat": file_format,
        "exportParameters": {
            "hideDevAndTestDependencies": False,
            "showOnlyEffectiveLicenses": False,
            "excludePackages": False,
            "excludeLicenses": False,
            "excludeVulnerabilities": False,
            "excludePolicies": False
        }
    }
    res = requests.post(f"{API_BASE_URL}/sca/export/requests", json=payload, headers=headers)
    if res.status_code == 202:
        return res.json().get("exportId")
    else:
        print(f"❌ Failed to create report for scan ID {scan_id}: {res.status_code} {res.text}")
        return None

def get_extension_from_format(file_format):
    if file_format == "ScanReportCsv": return "zip"
    elif file_format == "ScanReportPdf": return "pdf"
    elif file_format in {"ScanReportJson", "CycloneDxJson", "SpdxJson", "RemediatedPackagesJson"}: return "json"
    elif file_format in {"CycloneDxXml", "ScanReportXml"}: return "xml"
    return "bin"

def write_to_csv(results, filename="sca_export_reports.csv"):
    with open(filename, mode='w', newline='') as csvfile:
        fieldnames = ["Project Name", "Project ID", "Application Name", "Last SCA Scan ID", "Format","Export ID"]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)
    print(f"📄 Export completed: {filename}")

def main():
    token = get_access_token()
    if not token: return

    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}
    projects = get_all_projects(headers)
    if not projects:
        print("⚠️ No projects found.")
        return

    app_map = get_application_map(headers)

    # 🔍 Filter projects by application name if set
    if INCLUDED_APP_LIST:
        print(f"🔎 Filtering for application names: {INCLUDED_APP_LIST}")
        valid_app_ids = {app_id for app_id, name in app_map.items() if name in INCLUDED_APP_LIST}
        filtered_projects = []
        for proj in projects:
            app_ids = proj.get("applicationIds") or []
            if not isinstance(app_ids, list):
                app_ids = [app_ids]
            # Check if *any* of the app_ids match the included app list
            if any(app_id in valid_app_ids for app_id in app_ids):
                filtered_projects.append(proj)
        projects = filtered_projects

        if not projects:
            print("⚠️ No matching projects found for specified applications.")
            return


    results = []

    for proj in projects:
        pid, pname = proj["id"], proj["name"]
        print(f"🔍 {pname} ({pid})")

        scan_id = get_last_sca_scan_id(pid, headers)
        if not scan_id: continue

        application_ids = proj.get("applicationIds") or []
        if not isinstance(application_ids, list):
            application_ids = [application_ids]

        if not application_ids:
            application_ids = ["NoAppID"]

        for app_id in application_ids:
            app_name = app_map.get(app_id, "NoAppID")
            if INCLUDED_APP_LIST and app_name not in INCLUDED_APP_LIST:
                continue
            for file_format in FILE_FORMATS:
                export_id = create_report(scan_id, headers, file_format)
                results.append({
                    "Project Name": pname,
                    "Project ID": pid,
                    "Application Name": app_name,
                    "Last SCA Scan ID": scan_id,
                    "Format":file_format,
                    "Export ID": export_id or f"Could not create {file_format} report."
                })

                if not export_id:
                    continue

                for _ in range(RETRIES):
                    stat = requests.get(f"{API_BASE_URL}/sca/export/requests", headers=headers, params={"exportId": export_id}).json()
                    if stat.get("exportStatus") == "Completed":
                        file_url = stat.get("fileUrl")
                        response = requests.get(file_url, headers=headers)

                        sanitized_app = sanitize_filename(app_name)
                        sanitized_proj = sanitize_filename(pname)
                        extension = get_extension_from_format(file_format)
                        timestamp = get_current_timestamp()

                        if file_format in ["CycloneDxJson", "CycloneDxXml"]:
                            file_name = f"{sanitized_app}-{sanitized_proj}-1.6-{timestamp}-CycloneDx.{extension}"
                        elif file_format == "SpdxJson":
                            file_name = f"{sanitized_app}-{sanitized_proj}-2.2-{timestamp}-Spdx.{extension}"
                        else:
                            file_name = f"{sanitized_app}-{sanitized_proj}-{timestamp}-{file_format}.{extension}"

                        write_mode = "w" if extension == "json" else "wb"
                        with open(file_name, write_mode) as f:
                            if extension == "json":
                                json.dump(response.json(), f, indent=2)
                            else:
                                f.write(response.content)

                        print(f"✅ Wrote report: {file_name}")
                        break
                    elif stat.get("exportStatus") == "Failed":
                        print(f"❌ Failed export: {pname} ({file_format})")
                        break
                    time.sleep(DELAY)

    write_to_csv(results)

if __name__ == "__main__":
    main()
