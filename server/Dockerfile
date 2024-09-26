# Step 1: Usa un'immagine base di Python
FROM python:3.12-slim

# Step 2: Imposta la directory di lavoro
WORKDIR /app

# Step 3: Copia il file requirements.txt nella directory di lavoro
COPY requirements.txt .

# Step 4: Installa le dipendenze
RUN pip install --no-cache-dir -r requirements.txt

# Step 5: Copia il codice sorgente nella directory di lavoro
COPY app.py .
COPY probe.py .
COPY local_data.db .
COPY cert.pem .
COPY key.pem .
COPY static/ ./static
COPY templates/ ./templates

# Step 6: Espone la porta 8080
EXPOSE 5454

# Step 7: Avvia il server con app.py
CMD ["python", "app.py"]
