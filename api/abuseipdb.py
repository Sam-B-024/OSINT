#Authentication: API Key (included in the request headers)
#Example Query (Python):
#import requests

#API_KEY = "your_abuseipdb_api_key"
#IP = "8.8.8.8"
#URL = f"https://api.abuseipdb.com/api/v2/check?ipAddress={IP}"

#HEADERS = {
#	"Accept": "application/json",
#	"Key": API_KEY
#}

#response = requests.get(URL, headers=HEADERS)
#print(response.json())

import requests

def abuseipdb_check_ip(ip_address, api_key):
    """
    Check if an IP address has been reported for abuse on AbuseIPDB
    """
    url = "https://api.abuseipdb.com/api/v2/check"
    headers = {
        "Key": api_key,
        "Accept": "application/json"
    }
    params = {
        "ipAddress": ip_address,
        "maxAgeInDays": 90
    }

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
        print(f" Error checking IP in AbuseIPDB: {e}")
        return None
