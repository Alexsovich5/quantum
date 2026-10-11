#!/bin/sh
# Generate self-signed, test-only certificates, private keys and DH parameters
# under tests/fixtures/tls. None of this material protects anything real.
#
# Certificates are issued with `openssl ca -selfsign` so the validity window is
# fixed (ten years from 2020-06-01) instead of depending on when the script runs;
# tests that check validity use a fixed "now" inside that window.
set -eu

OUT=${1:-tests/fixtures/tls}
START=20200601000000Z
END=20300601000000Z

mkdir -p "$OUT"
WORK=$(mktemp -d)
trap 'rm -rf "$WORK"' EXIT

cat > "$WORK/ca.cnf" <<EOF
[ ca ]
default_ca = test_ca

[ test_ca ]
dir              = $WORK
database         = \$dir/index.txt
new_certs_dir    = \$dir
serial           = \$dir/serial
policy           = policy_any
unique_subject   = no
copy_extensions  = none
default_days     = 3650

[ policy_any ]
commonName       = supplied
organizationName = optional

[ req ]
distinguished_name = req_dn
prompt             = no

[ req_dn ]
CN = placeholder
EOF

issue() {
    name=$1
    keyalg=$2
    md=$3

    case "$keyalg" in
        rsa2048) openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 \
                     -out "$OUT/$name-key.pem" 2>/dev/null ;;
        p256)    openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 \
                     -out "$OUT/$name-key.pem" ;;
    esac

    : > "$WORK/index.txt"
    openssl rand -hex 16 > "$WORK/serial"
    printf '%s\n' \
        'basicConstraints = critical, CA:FALSE' \
        'keyUsage = critical, digitalSignature, keyEncipherment' \
        'extendedKeyUsage = serverAuth' \
        "subjectAltName = DNS:$name.test, DNS:localhost" \
        > "$WORK/ext.cnf"

    openssl req -new -config "$WORK/ca.cnf" -key "$OUT/$name-key.pem" \
        -subj "/O=quantum test fixtures/CN=$name.test" -out "$WORK/$name.csr"
    openssl ca -batch -config "$WORK/ca.cnf" -selfsign -notext \
        -keyfile "$OUT/$name-key.pem" -in "$WORK/$name.csr" \
        -startdate "$START" -enddate "$END" -md "$md" \
        -extfile "$WORK/ext.cnf" -out "$OUT/$name-cert.pem" 2>/dev/null
}

issue rsa2048-sha256 rsa2048 sha256
issue ec-p256-sha256 p256 sha256
issue rsa2048-sha1 rsa2048 sha1

openssl x509 -in "$OUT/rsa2048-sha256-cert.pem" -outform DER -out "$OUT/rsa2048-sha256-cert.der"
openssl dhparam -out "$OUT/dhparam-2048.pem" 2048 2>/dev/null

chmod 644 "$OUT"/*
ls -l "$OUT"
