#!/bin/bash
# Script to view Apache access logs from the SQLi lab container

echo "=== Standard Access Logs ==="
gcloud compute ssh sqli-lab --zone=us-central1-a --command="docker exec sqli-labs-sanitized tail -20 /var/log/apache2/access.log"

echo ""
echo "=== Detailed Access Logs (with response times) ==="
gcloud compute ssh sqli-lab --zone=us-central1-a --command="docker exec sqli-labs-sanitized tail -20 /var/log/apache2/detailed_access.log"

echo ""
echo "=== To follow logs in real-time, run: ==="
echo "gcloud compute ssh sqli-lab --zone=us-central1-a --command=\"docker exec sqli-labs-sanitized tail -f /var/log/apache2/access.log\""
