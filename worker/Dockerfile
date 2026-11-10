FROM python:3.13-slim
WORKDIR /srv
RUN useradd -u 10001 -m worker && mkdir /data && chown 10001:10001 /data
COPY --chown=10001:10001 worker /srv/worker
USER 10001
ENV PYTHONUNBUFFERED=1
CMD ["python","-m","worker.agent.main"]
