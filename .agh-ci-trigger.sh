#!/bin/sh
# Trigger the image.yaml workflow on the fork and show the newest run.
export HTTPS_PROXY=http://127.0.0.1:1080
export HTTP_PROXY=http://127.0.0.1:1080

gh workflow run image.yaml -R ciaoly/AdGuardHome --ref feat/querylog-syslog
echo "TRIGGERED exit=$?"
