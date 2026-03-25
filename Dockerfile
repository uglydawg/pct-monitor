FROM python:3.12-slim

WORKDIR /app
COPY monitor.py .

CMD ["python3", "monitor.py"]
