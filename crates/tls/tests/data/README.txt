Test certificates for sibuna-tls
================================

These files are fixed test data. They protect nothing: the private keys are public on
purpose, and the test CA's own key was discarded after signing. All keys are ECDSA P-256.

  ca.pem              Test CA "Sibuna Test CA", valid 2026-01-01 to 2126-01-01.
  localhost.pem/.key  Leaf signed by the test CA for DNS:localhost, IP:127.0.0.1, IP:::1,
                      valid 2026-01-01 to 2126-01-01.
  wrong-name.pem/.key Leaf signed by the test CA for DNS:wrong.example only.
  expired.pem/.key    Leaf signed by the test CA for localhost, valid only in the year 2000.
  untrusted.pem/.key  Self-signed leaf for localhost and 127.0.0.1, signed by no CA we trust.

They were made once with OpenSSL 3.5 (the -not_before and -not_after options need 3.4 or
later). To make a new set, run the following in a POSIX shell from this directory; ca.key
is written to a temporary directory and not kept.

  W=$(mktemp -d)
  V="-not_before 20260101000000Z -not_after 21260101000000Z"
  gen() { openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "$1"; }
  gen $W/ca.key
  openssl req -x509 -new -key $W/ca.key -subj "/CN=Sibuna Test CA" $V -sha256 \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem
  leaf() {
    name=$1; san=$2; shift 2
    gen $name.key
    openssl req -new -key $name.key -subj "/CN=$name" -out $W/$name.csr
    printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth\nsubjectAltName=%s\n" "$san" > $W/$name.ext
    openssl x509 -req -in $W/$name.csr -CA ca.pem -CAkey $W/ca.key -sha256 \
      -extfile $W/$name.ext "$@" -out $name.pem
  }
  leaf localhost "DNS:localhost,IP:127.0.0.1,IP:::1" $V
  leaf wrong-name "DNS:wrong.example" $V
  leaf expired "DNS:localhost,IP:127.0.0.1" \
    -not_before 20000101000000Z -not_after 20010101000000Z
  gen untrusted.key
  openssl req -x509 -new -key untrusted.key -subj "/CN=localhost" $V -sha256 \
    -addext "basicConstraints=critical,CA:FALSE" \
    -addext "keyUsage=critical,digitalSignature" \
    -addext "extendedKeyUsage=serverAuth" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" -out untrusted.pem
  chmod 644 *.pem *.key
