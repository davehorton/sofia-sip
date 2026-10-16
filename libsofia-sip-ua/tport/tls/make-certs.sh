#!/bin/sh
#
# Regenerate the test PKI used by check_tport: a CA, a server certificate
# for localhost/127.0.0.1 and a client certificate with its own identity
# (for mutual TLS). Each .pem holds the key and the certificate.
#
# usage: cd libsofia-sip-ua/tport/tls && ./make-certs.sh

set -e
days=36500
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

openssl req -x509 -newkey rsa:2048 -nodes -days $days \
  -subj "/O=sofia-sip test/CN=sofia-sip check_tport CA" \
  -keyout "$tmp/ca.key" -out ca.pem

node() {
  name=$1 subj=$2 ext=$3
  openssl req -newkey rsa:2048 -nodes -subj "$subj" \
    -keyout "$tmp/$name.key" -out "$tmp/$name.csr"
  printf '%s\n' "$ext" > "$tmp/$name.ext"
  openssl x509 -req -in "$tmp/$name.csr" -days $days \
    -CA ca.pem -CAkey "$tmp/ca.key" -CAserial "$tmp/ca.srl" -CAcreateserial \
    -extfile "$tmp/$name.ext" -out "$tmp/$name.crt"
  cat "$tmp/$name.key" "$tmp/$name.crt" > "$name.pem"
}

node server "/O=sofia-sip test/CN=localhost" \
  "subjectAltName=DNS:localhost,IP:127.0.0.1
extendedKeyUsage=serverAuth,clientAuth"
node client "/O=sofia-sip test/CN=sofia-sip test client" \
  "subjectAltName=DNS:client.example.org
extendedKeyUsage=clientAuth"
