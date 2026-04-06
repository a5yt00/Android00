#!/bin/bash
# Pre-create the directory structure
mkdir -p androidaudit/modules/static androidaudit/modules/dynamic/scripts androidaudit/modules/network androidaudit/modules/storage androidaudit/report/templates tests/fixtures

# Create empty __init__.py files
find androidaudit -type d -exec touch {}/__init__.py \;
touch tests/__init__.py

# Create the .env.example
cat <<EOT > .env.example
ADB_SERIAL=emulator-5554
TARGET_PACKAGE=com.example.targetapp
FRIDA_SERVER_PATH=/data/local/tmp/frida-server
OUTPUT_DIR=./reports
EOT

echo "Scaffold complete. Ready for agent injection."