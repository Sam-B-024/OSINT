#Authentication: API Key (included in the request headers)
#Example Query (Python):
#import requests

#API_KEY = "your_virustotal_api_key"
#URL = "https://www.virustotal.com/api/v3/ip_addresses/8.8.8.8"
#HEADERS = {"x-apikey": API_KEY}

#response = requests.get(URL, headers=HEADERS)
#print(response.json())

import requests

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

    except requests.exceptions.HTTPError as http_err:
        print(f" HTTP error occurred in VirusTotal request: {http_err}")
        return None
    except Exception as err:
        print(f" Other error occurred in VirusTotal request: {err}")
        return None

