# PII-Safe web dashboard + REST API.
#   docker build -t piisafe .
#   docker run -p 127.0.0.1:8765:8765 -v piisafe-data:/data piisafe
# The first start prints a one-time admin API key: docker logs <container>
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PIISAFE_HOME=/data

WORKDIR /app
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip install --no-cache-dir ".[server,ner,postgres,aws,mcp]" \
 && python -m spacy download en_core_web_sm \
 && useradd --system --uid 10001 piisafe \
 && mkdir -p /data && chown piisafe /data && chmod 700 /data

USER piisafe
VOLUME /data
EXPOSE 8765
HEALTHCHECK CMD python -c "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8765/api/health')"
CMD ["piisafe", "serve", "--host", "0.0.0.0", "--port", "8765"]
