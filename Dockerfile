# Portail Captif SSO RBER v2 — image non-root, sans outils reseau locaux
# (le portail pilote les pfSense par API HTTPS, jamais le reseau local)
FROM python:3.12-slim

WORKDIR /opt/captive-portal

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY app ./app
COPY templates ./templates
COPY themes ./themes
COPY static ./static

# Compatible PodSecurity "restricted"
RUN useradd --uid 10001 --no-create-home portal
USER 10001

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
  CMD python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8000/health')" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000", "--proxy-headers"]
