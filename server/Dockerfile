FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY app.py .
COPY probe.py .
COPY static/ ./static
COPY templates/ ./templates
EXPOSE 5454
CMD ["python", "app.py"]
