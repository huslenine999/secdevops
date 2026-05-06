FROM python:3.9-slim-buster

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY scripts ./scripts
COPY policy_engine.py .

RUN python scripts/seed_db.py

EXPOSE 5000

CMD ["python", "app/main.py"]
