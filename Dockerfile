# Use python image
FROM python:3.9-slim

# Set directory
WORKDIR /app

COPY . /app

#Sets up venv
RUN python3 -m venv venv

#Downloads all dependencies
RUN ./venv/bin/pip install --no-cache-dir -r requirements.txt

# Set the path for the venv
ENV PATH="/app/venv/bin:$PATH"

# Run the app 
CMD ["python3", "src/app.py"]

