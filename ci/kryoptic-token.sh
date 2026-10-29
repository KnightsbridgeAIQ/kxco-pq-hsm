#!/bin/bash
# A fresh kryoptic token in /tmp/kry with user PIN 1234.
set -euo pipefail
mkdir -p /tmp/kry
printf '[[slots]]\nslot = 42\ndbtype = "sqlite"\ndbargs = "/tmp/kry/token.sql"\n' > "$KRYOPTIC_CONF"
rm -f /tmp/kry/token.sql
pkcs11-tool --module "$HSM_ML_KEM_LIBRARY_PATH" --init-token --label kxco-test --so-pin 12345678 >/dev/null
pkcs11-tool --module "$HSM_ML_KEM_LIBRARY_PATH" --login --login-type so --so-pin 12345678 --init-pin --pin "$HSM_PIN" >/dev/null
