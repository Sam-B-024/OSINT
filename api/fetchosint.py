import os
import psycopg2
from dotenv import load_dotenv

#  Import your API functions
from virustotal import virustotal_get_ip_report
from abuseipdb import abuseipdb_check_ip
from securitytrails import query_securitytrails

#  Load environment variables from .env
dotenv_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "OSINT.env"))
load_dotenv(dotenv_path)

#  Get API keys from environment
vt_api_key = os.getenv("VIRUSTOTAL_API_KEY")
st_api_key = os.getenv("SECURITYTRAILS_API_KEY")
abuseipdb_api_key = os.getenv("ABUSEIPDB_API_KEY")

#  IP and Domain to query
ip = "8.8.8.8"
domain = "example.com"

#  Fetch threat data
vt_data = virustotal_get_ip_report(ip, vt_api_key)
abuse_data = abuseipdb_check_ip(ip, abuseipdb_api_key)
st_data = query_securitytrails(domain, st_api_key)

#  Connect to PostgreSQL and insert data
try:
    conn = psycopg2.connect(
        dbname="threat_intel",
        user="postgres",            # ← Update if your user is different
        password="your_password",   # ← Replace with your real PostgreSQL password
        host="localhost",
        port="5432"
    )
    cursor = conn.cursor()

    # 🧪 Debug print
    print("🛠 Preparing to insert data into threat_data table...")
    print("Insert values:")
    print((
        ip,
        vt_data.get("reputation"),
        abuse_data.get("abuseConfidenceScore"),
        abuse_data.get("totalReports"),
        domain,
        st_data.get("createdDate"),
        st_data.get("registrar")
    ))

    #  Insert into table
    cursor.execute("""
        INSERT INTO threat_data (
            ip, vt_reputation, abuse_score, total_reports,
            domain, created_date, registrar
        ) VALUES (%s, %s, %s, %s, %s, %s, %s)
    """, (
        ip,
        vt_data.get("reputation"),
        abuse_data.get("abuseConfidenceScore"),
        abuse_data.get("totalReports"),
        domain,
        st_data.get("createdDate"),
        st_data.get("registrar")
    ))

    conn.commit()
    print(" Threat data successfully stored in database.")

except Exception as e:
    print(" Error inserting into database:")
    raise e

finally:
    if conn:
        cursor.close()
        conn.close()
