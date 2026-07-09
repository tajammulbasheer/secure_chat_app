FROM python:3.10-slim

WORKDIR /app

# Copy requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application packages
COPY shared/ ./shared/
COPY server/ ./server/

# Set environment paths and exposure
ENV PYTHONPATH=/app
EXPOSE 6000

# Execute KDC server
CMD ["python", "-m", "server.sts"]
