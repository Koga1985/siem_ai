FROM python:3.11-slim
WORKDIR /app
COPY services/ai_generator/requirements.txt requirements.txt
RUN pip install --no-cache-dir -r requirements.txt
COPY services/ai_generator /app
CMD ["python", "main.py"]
