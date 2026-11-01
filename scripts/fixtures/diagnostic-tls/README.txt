Public loopback test fixture, generated for AccessWeaver under the repository's 0BSD license.
The private key is intentionally public and provides no identity assurance. Never use this key/certificate in production or import it into a trust store.
The self-signed non-CA server certificate is used only to require packaged diagnostics to reject an untrusted localhost TLS peer. No OS trust configuration is changed.
Regenerate with OpenSSL req -x509 -newkey rsa:2048 -nodes -sha256, the localhost/127.0.0.1 subjectAltName, CA:FALSE, serverAuth and digitalSignature/keyEncipherment extensions when rotating this fixture.
