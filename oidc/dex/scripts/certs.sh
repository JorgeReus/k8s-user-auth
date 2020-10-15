#!/bin/bash

OUTPUT_DIR="../certs"
NUM_BITS=2048
EXPIRE_DAYS=365
DNS_NAME=$1
if [ -z $DNS_NAME ];then
  echo "Error: First argument should be the dns name of the request"
  echo "  Usage: ./certs.sh my.domain.name"
  exit 1
fi
mkdir -p  $OUTPUT_DIR

cat << EOF > $OUTPUT_DIR/req.cnf
[req]
req_extensions = v3_req
distinguished_name = req_distinguished_name

[req_distinguished_name]

[ v3_req ]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
subjectAltName = @alt_names

[alt_names]
DNS.1 = $DNS_NAME
EOF

openssl genrsa -out $OUTPUT_DIR/ca-key.pem $NUM_BITS
openssl req -x509 -new -nodes -key $OUTPUT_DIR/ca-key.pem -days 10 -out $OUTPUT_DIR/ca.pem -subj "/CN=kube-ca"

openssl genrsa -out $OUTPUT_DIR/key.pem $NUM_BITS
openssl req -new -key $OUTPUT_DIR/key.pem -out $OUTPUT_DIR/csr.pem -subj "/CN=kube-ca" -config $OUTPUT_DIR/req.cnf
openssl x509 -req -in $OUTPUT_DIR/csr.pem -CA $OUTPUT_DIR/ca.pem -CAkey $OUTPUT_DIR/ca-key.pem -CAcreateserial -out $OUTPUT_DIR/cert.pem -days $EXPIRE_DAYS -extensions v3_req -extfile $OUTPUT_DIR/req.cnf
