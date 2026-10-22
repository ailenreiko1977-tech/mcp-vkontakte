FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app
COPY requirements.lock ./
RUN pip install --no-cache-dir -r requirements.lock && useradd --uid 10001 --create-home app && mkdir /data && chown app:app /data
COPY vk_mcp ./vk_mcp
COPY scripts/cleanup.py ./scripts/cleanup.py
USER 10001:10001
EXPOSE 8000
CMD ["python", "-m", "vk_mcp.app"]
