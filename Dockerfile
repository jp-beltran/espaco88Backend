FROM python:3.9-slim

WORKDIR /app

COPY requirements.txt .
RUN apt-get update && apt-get install -y \
    gcc \
    libpq-dev \
    build-essential \
    && pip install --no-cache-dir -r requirements.txt

COPY . .

# Adiciona o script de espera
COPY wait-for-it.sh /wait-for-it.sh
RUN chmod +x /wait-for-it.sh

EXPOSE 5000

CMD ["python", "app.py"]
