FROM python:3.11-slim
WORKDIR /app
RUN pip install flask ansible
COPY services/orchestrator /app
EXPOSE 8088
CMD ["python", "pr.py"]
