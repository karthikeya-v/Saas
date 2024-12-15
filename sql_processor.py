import os
import mysql.connector
import re
from datetime import datetime

# MySQL database configuration
db_config = {
    "host": os.getenv("DB_HOST"),
    "user": os.getenv("DB_USER"),
    "password": os.getenv("DB_PASSWORD"),
    "database": os.getenv("DB_NAME"),
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

# Function to parse the dns.log file
def parse_dns_log(file_path):
    dns_data = []
    with open(file_path, "r") as log_file:
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

# Main function
def main():
    create_dns_table()
    dns_data = parse_dns_log("/app/dns.log")
    insert_dns_data(dns_data)

if __name__ == "__main__":
    main()
