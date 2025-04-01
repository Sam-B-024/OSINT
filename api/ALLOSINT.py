import os
import requests
import json
from dotenv import load_dotenv

#  Load the .env file explicitly
dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "OSINT.env"))
load_dotenv(dotenv_path)

#  Assign API keys properly
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
st_api_key = os.getenv("SECURITYTRAILS_API_KEY")
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

#  Debugging: Print API keys to ensure they are loaded correctly
print("VirusTotal API Key:", vt_api_key)
print("SecurityTrails API Key:", st_api_key)
print("AbuseIPDB API Key:", abuseipdb_api_key)

#  Exit early if any API key is missing
if not vt_api_key or not st_api_key or not abuseipdb_api_key:
    print(" ERROR: One or more API keys are missing. Check your OSINT.env file.")
    exit(1)


# =========== VirusTotal API Integration ===========
def virustotal_get_ip_report(ip_address, api_key):
    """
    Get information about an IP address from VirusTotal
    """
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip_address}"
    headers = {"x-apikey": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Extract relevant information
        return {
            "reputation": data.get("data", {}).get("attributes", {}).get("reputation", "N/A"),
            "last_analysis_stats": data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        }
    except requests.exceptions.RequestException as e:
        print(f"Error getting IP report from VirusTotal: {e}")
        return None


# =========== SecurityTrails API Integration (Reverted to Original) ===========
def query_securitytrails(domain, api_key):
    """
    Get information about a domain from SecurityTrails
    """
    url = f"https://api.securitytrails.com/v1/domain/example.com"
    headers = {"APIKEY": api_key}
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        # Extract relevant information
        return {
            "hostname": domain,
            "createdDate": data.get("created_date", "N/A"),
            "registrar": data.get("registrar", {}).get("name", "N/A")
        }
    except requests.exceptions.RequestException as e:
        print(f"Error querying SecurityTrails: {e}")
        return None


# =========== AbuseIPDB API Integration ===========
def abuseipdb_check_ip(ip_address, api_key):
    """
    Check if an IP address has been reported for abuse on AbuseIPDB
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {"ipAddress": ip_address, "maxAgeInDays": 90}
    try:
        response = requests.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        # Extract relevant information
        return {
            "ipAddress": ip_address,
            "abuseConfidenceScore": data.get("data", {}).get("abuseConfidenceScore", "N/A"),
            "totalReports": data.get("data", {}).get("totalReports", "N/A")
        }
    except requests.exceptions.RequestException as e:
        print(f"Error checking IP in AbuseIPDB: {e}")
        return None


# =========== Formatted Output Function ===========
def print_formatted_output(title, data):
    """
    Print data in a formatted manner
    """
    print(f"\n=== {title} ===")
    print(json.dumps(data, indent=2) if data else "No data available")


# =========== Example Usage ===========
if __name__ == "__main__":
    domain = "example.com"
    ip_address = "8.8.8.8"

    #  Fetch and print SecurityTrails data
    st_data = query_securitytrails(domain, st_api_key)
    print_formatted_output("SecurityTrails Data", st_data)

    #  Fetch and print VirusTotal data
    vt_data = virustotal_get_ip_report(ip_address, vt_api_key)
    print_formatted_output("VirusTotal IP Report", vt_data)

    #  Fetch and print AbuseIPDB data
    abuseipdb_data = abuseipdb_check_ip(ip_address, abuseipdb_api_key)
    print_formatted_output("AbuseIPDB IP Report", abuseipdb_data)
