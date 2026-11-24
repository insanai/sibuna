Test certificates for client authentication
===========================================

These files are fixed test data. They protect nothing: the private key is public on
purpose, and the CA's own key was discarded after signing. All keys are ECDSA P-256.

  client-ca.pem      Test CA "Sibuna Test Client CA", valid 2026-01-01 to 2126-01-01.
  client.pem/.key    Leaf "test-client" signed by that CA for client authentication.

The server certificates are in ../../../tls/tests/data. These were made once with OpenSSL
3.5, the same way as that set: a CA with keyCertSign, and a leaf with
extendedKeyUsage=clientAuth and no subject alternative name.
