FROM python:slim-trixie

WORKDIR /app

COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

COPY main.py .
COPY ca.crt .
COPY .env .

CMD ["python", "-u", "main.py"]