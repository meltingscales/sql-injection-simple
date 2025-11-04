# SQLi-Labs Cloud Run Deployment
# Deploys to Google Cloud Run with automatic *.run.app domain

# Default recipe - show available commands
default:
    @just --list

# Deploy to Cloud Run (gets automatic *.run.app domain)
deploy PROJECT_ID:
    #!/usr/bin/env bash
    set -euo pipefail
    cd politically-correct-data
    # Build image with Cloud Build
    gcloud builds submit \
      --tag gcr.io/{{PROJECT_ID}}/sqli-lab \
      --project={{PROJECT_ID}}
    # Deploy to Cloud Run
    gcloud run deploy sqli-lab \
      --image gcr.io/{{PROJECT_ID}}/sqli-lab \
      --platform managed \
      --region us-central1 \
      --allow-unauthenticated \
      --port 8080 \
      --memory 1Gi \
      --cpu 2 \
      --timeout 300 \
      --max-instances 1 \
      --min-instances 0 \
      --cpu-boost \
      --project={{PROJECT_ID}}
    echo ""
    echo "Deployment complete! Your URL:"
    gcloud run services describe sqli-lab \
      --region us-central1 \
      --project={{PROJECT_ID}} \
      --format='value(status.url)'

# Get service URL
get-url PROJECT_ID:
    gcloud run services describe sqli-lab \
      --region us-central1 \
      --project={{PROJECT_ID}} \
      --format='value(status.url)'

# View logs
logs PROJECT_ID:
    gcloud run services logs read sqli-lab \
      --region us-central1 \
      --project={{PROJECT_ID}} \
      --limit 50

# Follow logs in real-time
logs-follow PROJECT_ID:
    gcloud run services logs tail sqli-lab \
      --region us-central1 \
      --project={{PROJECT_ID}}

# Delete service
delete PROJECT_ID:
    gcloud run services delete sqli-lab \
      --region us-central1 \
      --project={{PROJECT_ID}}

# Test connection
test PROJECT_ID:
    #!/usr/bin/env bash
    URL=$(gcloud run services describe sqli-lab --region us-central1 --project={{PROJECT_ID}} --format='value(status.url)')
    curl -s "$URL/Less-1/" | head -20
