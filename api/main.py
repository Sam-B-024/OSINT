from dotenv import load_dotenv
import os


# Load environment variables from .env file
load_dotenv()


# Retrieve API keys
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
domain = "example.com"


abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")


# Debugging: Print the keys to verify they are loaded (Remove this in production)
print(f"VirusTotal API Key: {vt_api_key}")
print(f"AbuseIPDB API Key: {abuseipdb_api_key}")
print(f"SecurityTrails API Key: {os.getenv('SECURITYTRAILS_API_KEY')}")
from dotenv import dotenv_values