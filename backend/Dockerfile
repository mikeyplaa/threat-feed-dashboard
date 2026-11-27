FROM python:3.12-slim

WORKDIR /app

# Optional extra root CAs, e.g. a corporate TLS-inspection proxy (iboss).
# Drop PEM-encoded *.crt files into backend/certs/ (gitignored). They're added
# to the system bundle alongside the normal Mozilla roots; verification stays on.
COPY certs/ /usr/local/share/ca-certificates/extra/
RUN update-ca-certificates \
 && (ls /usr/local/share/ca-certificates/extra/*.crt >/dev/null 2>&1 \
     || echo "WARNING: backend/certs/ has no *.crt - behind iboss, run scripts/export-proxy-ca.ps1 first or every feed will fail TLS verification")
ENV SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt \
    PIP_CERT=/etc/ssl/certs/ca-certificates.crt

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8070

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8070"]
