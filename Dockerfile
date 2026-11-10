FROM python:3.13-slim
WORKDIR /srv
COPY requirements.txt /srv/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt && useradd -u 10001 -m scanlattice && mkdir -p /data && chown 10001:10001 /data
COPY app /srv/app
COPY migrations /srv/migrations
USER 10001
ENV DATABASE_PATH=/data/scanlattice.db
EXPOSE 8080
CMD ["uvicorn","app.main:app","--host","0.0.0.0","--port","8080","--proxy-headers","--forwarded-allow-ips","127.0.0.1"]
