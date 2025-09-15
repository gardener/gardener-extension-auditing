#!/bin/bash

# SPDX-FileCopyrightText: SAP SE or an SAP affiliate company and Gardener contributors
#
# SPDX-License-Identifier: Apache-2.0
# 

set -o errexit
set -o pipefail

repo_root="$(readlink -f $(dirname ${0})/..)"
cert_dir="$repo_root/example/local-setup/dev/certs"

mkdir -p "$cert_dir"

if [[ -s "$cert_dir/tls.key" ]]; then
    echo "Development certificate found at $cert_dir. Skipping generation..."
    exit 0
fi

echo "Generating Certificate Authority (CA)..."
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -days 365 \
  -nodes -keyout "$cert_dir/ca.key" -out "$cert_dir/ca.crt" \
  -subj "/CN=Local Development CA"

echo "Generating development certificate for echo-server..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$cert_dir/echo-server-tls.key" -out "$cert_dir/echo-server-tls.csr" \
  -subj "/CN=echo-server" -addext "subjectAltName=DNS:localhost,DNS:echo-server,DNS:echo-server.echo-server,DNS:echo-server.echo-server.svc,DNS:echo-server.echo-server.svc.cluster.local,IP:127.0.0.1"

openssl x509 -req -in "$cert_dir/echo-server-tls.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
  -out "$cert_dir/echo-server-tls.crt" -days 365 \
  -extensions v3_req -extfile <(echo "[v3_req]"; echo "keyUsage = keyEncipherment, digitalSignature"; echo "extendedKeyUsage = serverAuth"; echo "subjectAltName=DNS:localhost,DNS:echo-server,DNS:echo-server.echo-server,DNS:echo-server.echo-server.svc,DNS:echo-server.echo-server.svc.cluster.local,IP:127.0.0.1")

echo "Generating client certificate for auditlog-forwarder..."
openssl req -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 -nodes \
  -keyout "$cert_dir/client.key" -out "$cert_dir/client.csr" \
  -subj "/CN=auditlog-forwarder-client"

openssl x509 -req -in "$cert_dir/client.csr" -CA "$cert_dir/ca.crt" -CAkey "$cert_dir/ca.key" -CAcreateserial \
  -out "$cert_dir/client.crt" -days 365 \
  -extensions v3_req -extfile <(echo "[v3_req]"; echo "keyUsage = digitalSignature"; echo "extendedKeyUsage = clientAuth")

# Clean up CSR files
rm -f "$cert_dir/tls.csr" "$cert_dir/echo-server-tls.csr" "$cert_dir/client.csr" "$cert_dir/kube-apiserver-client.csr"
