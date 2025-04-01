#import os
#import requests
#from dotenv import load_dotenv

# Load OSINT.env
#load_dotenv("OSINT.env")

# Retrieve SecurityTrails API key
#st_api_key = os.getenv("SECURITYTRAILS_API_KEY")

# Debugging: Print the API key before making a request
#print(f"SecurityTrails API Key: {st_api_key}")  # Should NOT be None


#def query_securitytrails(domain):
#    url = url = f"https://api.securitytrails.com/v1/domain/example.com"
#    headers = {"API-Key": st_api_key}  # ✅ Correct API key header

#    response = requests.get(url, headers=headers)

#    print(f"Status Code: {response.status_code}")  # Print status code
#    print(f"Response Text: {response.text}")  # Print API response

#    if response.status_code == 200:
#        return response.json()
#    else:
#        print(f"Error: {response.status_code}, {response.text}")
#        return None


# Run test
#if __name__ == "__main__":
#    domain = "example.com"  # Change to a real domain if needed
#    data = query_securitytrails(domain)
#    print("SecurityTrails Data:", data if data else "No data available.")




import requests

def query_securitytrails(domain, api_key):
    """
    Get WHOIS info from SecurityTrails
    """
    url = f"https://api.securitytrails.com/v1/domain/{domain}/whois"
    headers = {"APIKEY": api_key}

    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        data = response.json()

        return {
            "hostname": domain,
            "createdDate": data.get("created_date", "N/A"),
            "registrar": data.get("registrar", {}).get("name", "N/A")
        }

    except requests.exceptions.RequestException as e:
        print(f" Error querying SecurityTrails: {e}")
        return None
