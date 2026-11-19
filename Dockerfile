FROM python:3.12-slim
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    CYBERSEC_HOME=/var/lib/cybersec
WORKDIR /app
RUN addgroup --system cybersec && adduser --system --ingroup cybersec --home /home/cybersec cybersec
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
RUN python -m pip install --no-cache-dir . && mkdir -p /var/lib/cybersec /var/log/cybersec && chown -R cybersec:cybersec /var/lib/cybersec /var/log/cybersec /app
USER cybersec
VOLUME ["/var/lib/cybersec", "/var/log/cybersec"]
ENTRYPOINT ["python", "-m", "cybersec"]
CMD ["init"]
