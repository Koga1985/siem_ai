FROM python:3.11-slim
WORKDIR /app
COPY services/event_bridge/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY services/event_bridge /app
CMD ["python", "app.py"]
