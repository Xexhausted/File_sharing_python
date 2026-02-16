# Use a lightweight Python image
FROM python:3.10-slim

# Set the working directory inside the container
WORKDIR /app

# Install system dependencies for Tkinter (GUI)
RUN apt-get update && apt-get install -y python3-tk tk && rm -rf /var/lib/apt/lists/*

# Copy requirements and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the source code and the secret key (so all nodes share the same key)
COPY src/ ./src/

# Default command (can be overridden in docker-compose)
CMD ["python", "src/main.py", "8888"]