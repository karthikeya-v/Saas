import os
import mysql.connector
import re
from datetime import datetime
import gzip
import csv

# MySQL database configuration
db_config = {
    "host": os.getenv("DB_HOST", "localhost"),
    "user": os.getenv("DB_USER", "zeek_user"),
    "password": os.getenv("DB_PASSWORD", "zeek_password"),
    "database": os.getenv("DB_NAME", "zeek_logs"),
}

# Function to create the DNS table if it doesn't exist
def create_dns_table():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS dns_queries (
            id INT AUTO_INCREMENT PRIMARY KEY,
            domain VARCHAR(255) NOT NULL,
            timestamp DATETIME NOT NULL
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()

# Function to create the SaaS data table if it doesn't exist
def create_saas_table():
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS saas_data (
            id INT AUTO_INCREMENT PRIMARY KEY,
            website VARCHAR(255),
            organization_name VARCHAR(255),
            industries VARCHAR(255),
            employee_count INT,
            phone VARCHAR(50),
            twitter VARCHAR(255),
            facebook VARCHAR(255),
            linkedin VARCHAR(255),
            country VARCHAR(100),
            city VARCHAR(100),
            description TEXT,
            whois_registrar VARCHAR(255),
            whois_created_date DATETIME,
            whois_referral_url VARCHAR(255)
        );
    """)
    conn.commit()
    cursor.close()
    conn.close()

# Function to parse the dns.log or dns.log.gz files
def parse_dns_log(file_path):
    dns_data = []
    open_file = gzip.open if file_path.endswith('.gz') else open
    with open_file(file_path, "rt") as log_file:
        for line in log_file:
            # Skip Zeek's log header
            if line.startswith("#"):
                continue
            fields = line.strip().split("\t")
            try:
                ts = fields[0]
                query = fields[9]
                if not is_ipv6(query) and not is_reverse_dns(query):
                    dt = datetime.fromtimestamp(float(ts)).strftime('%Y-%m-%d %H:%M:%S')
                    dns_data.append((dt, query))
            except (IndexError, ValueError):
                continue
    return dns_data

# Helper functions
def is_ipv6(domain):
    try:
        return bool(re.match(r"([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}", domain))
    except Exception:
        return False

def is_reverse_dns(domain):
    return domain.endswith(".arpa")

# Insert parsed data into MySQL
def insert_dns_data(dns_data):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    for ts, domain in dns_data:
        cursor.execute("""
            INSERT INTO dns_queries (timestamp, domain)
            VALUES (%s, %s);
        """, (ts, domain))
    conn.commit()
    cursor.close()
    conn.close()

# Function to import data from data_saas.csv
def import_csv_data(file_path):
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor()
    with open(file_path, "r") as csv_file:
        csv_reader = csv.reader(csv_file)
        next(csv_reader)  # Skip header row
        for row in csv_reader:
            try:
                website, organization_name, industries, employee_count, phone, twitter, facebook, linkedin, country, city, description, whois_registrar, whois_created_date, whois_referral_url, *_ = row
                cursor.execute("""
                    INSERT INTO saas_data (
                        website, organization_name, industries, employee_count, phone,
                        twitter, facebook, linkedin, country, city, description,
                        whois_registrar, whois_created_date, whois_referral_url
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
                """, (website, organization_name, industries, 
                       int(employee_count) if employee_count else None, phone, 
                       twitter, facebook, linkedin, country, city, description, 
                       whois_registrar, 
                       datetime.strptime(whois_created_date, '%Y-%m-%dT%H:%M:%S%z') if whois_created_date else None, 
                       whois_referral_url))
            except Exception as e:
                print(f"Error inserting row {row}: {e}")
    conn.commit()
    cursor.close()
    conn.close()

# Function to locate dns.log or dns.log.gz files
def find_dns_logs():
    base_dir = os.path.abspath(os.path.join(os.getcwd(), ".."))
    dns_files = []
    for root, dirs, files in os.walk(base_dir):
        # Only process directories named with "2024" or "current"
        if "2024" in root or "current" in root:
            for file in files:
                if file.endswith("dns.log") or file.endswith("dns.log.gz"):
                    dns_files.append(os.path.join(root, file))
    return dns_files

# Main function
def main():
    create_dns_table()
    create_saas_table()

    # Import data from data_saas.csv
    csv_file = "SaasData.csv"
    if os.path.exists(csv_file):
        print(f"Importing data from {csv_file}...")
        import_csv_data(csv_file)

    # Process dns.log files
    dns_files = find_dns_logs()
    for dns_file in dns_files:
        print(f"Processing {dns_file}...")
        dns_data = parse_dns_log(dns_file)
        insert_dns_data(dns_data)

if __name__ == "__main__":
    main()

