Self-signed TLS certificate and key for proxy

```
openssl req -x509 -newkey rsa:2048 -keyout tls.key -out tls.crt -sha256 -days 18250 -nodes \
  -subj "CN=localhost" \
  -addext "subjectAltName=DNS:kubernetes,DNS:kubernetes.default,DNS:kubernetes.default.svc,DNS:kubernetes.default.svc.cluster.local,DNS:localhost,IP:127.0.0.1,IP:0:0:0:0:0:0:0:1"
```
