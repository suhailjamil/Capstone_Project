FROM python:3.9-slim

WORKDIR /app

# Install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code
COPY src/ /app/src/

# Create data directories
RUN mkdir -p /app/data/raw /app/data/processed

# Set environment variables
ENV PYTHONPATH=/app

# Run the application
ENTRYPOINT ["python", "src/main.py"]
CMD ["--simulate"]
