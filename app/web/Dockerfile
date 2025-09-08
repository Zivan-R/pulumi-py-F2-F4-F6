FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIP_NO_CACHE_DIR=1
WORKDIR /app
COPY requirements.txt .
RUN pip install --upgrade pip && pip install -r requirements.txt
COPY main.py start.sh .
RUN chmod +x start.sh
EXPOSE 8000
HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD curl -fsS http://127.0.0.1:8000/health || exit 1
CMD ["./start.sh"]

