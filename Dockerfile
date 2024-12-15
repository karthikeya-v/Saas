# Use Python 3.9 as the base image
FROM python:3.9-slim

# Set the working directory
WORKDIR /app

# Copy the necessary files
COPY sql_processor.py /app/sql_processor.py
COPY dns.log /app/dns.log

# Install Python dependencies
RUN pip install mysql-connector-python pandas

# Command to keep the container alive for processing
CMD ["python3", "/app/sql_processor.py"]
