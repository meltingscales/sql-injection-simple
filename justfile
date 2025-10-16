# SQLi-Labs GCP Deployment
# Set PROJECT_ID environment variable before running

# Default recipe - show available commands
default:
    @just --list

# Create GCP Compute Engine instance
create-instance PROJECT_ID:
    gcloud compute instances create sqli-lab \
      --project={{PROJECT_ID}} \
      --zone=us-central1-a \
      --machine-type=e2-micro \
      --image-family=cos-stable \
      --image-project=cos-cloud \
      --boot-disk-size=10GB \
      --tags=http-server,https-server

# Create firewall rule to allow HTTP traffic
create-firewall PROJECT_ID:
    gcloud compute firewall-rules create allow-http-sqli \
      --project={{PROJECT_ID}} \
      --allow=tcp:80 \
      --target-tags=http-server

# Copy files to GCP instance
copy-files PROJECT_ID:
    gcloud compute scp --project={{PROJECT_ID}} --zone=us-central1-a --recurse politically-correct-data sqli-lab:~/

# SSH into the instance
ssh PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}}

# Build and run container on remote instance
deploy-container PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="\
      cd politically-correct-data && \
      docker build -t sqli-labs-sanitized . && \
      docker run -d -p 80:80 --name sqli-labs-sanitized sqli-labs-sanitized && \
      sudo iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT"

# Fix Container-Optimized OS firewall (run after SSH-ing in)
fix-firewall PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="sudo iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT"

# Get external IP address
get-ip PROJECT_ID:
    gcloud compute instances describe sqli-lab \
      --zone=us-central1-a \
      --project={{PROJECT_ID}} \
      --format='get(networkInterfaces[0].accessConfigs[0].natIP)'

# Complete setup (create instance, firewall, copy files, deploy)
setup PROJECT_ID: (create-instance PROJECT_ID) (create-firewall PROJECT_ID) (copy-files PROJECT_ID) (deploy-container PROJECT_ID)
    @echo "Setup complete! Get IP with: just get-ip {{PROJECT_ID}}"

# View recent Apache access logs
view-logs PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="docker exec sqli-labs-sanitized tail -20 /var/log/apache2/access.log"

# Follow Apache access logs in real-time
follow-logs PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="docker exec sqli-labs-sanitized tail -f /var/log/apache2/access.log"

# View detailed Apache logs with response times
view-detailed-logs PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="docker exec sqli-labs-sanitized tail -20 /var/log/apache2/detailed_access.log"

# Test connection with curl (requires IP as argument)
test-connection IP:
    curl -s "http://{{IP}}/Less-1/" | head -20

# Delete GCP instance
delete-instance PROJECT_ID:
    gcloud compute instances delete sqli-lab --zone=us-central1-a --project={{PROJECT_ID}}

# Delete firewall rule
delete-firewall PROJECT_ID:
    gcloud compute firewall-rules delete allow-http-sqli --project={{PROJECT_ID}}

# Complete cleanup (delete instance and firewall)
cleanup PROJECT_ID: (delete-instance PROJECT_ID) (delete-firewall PROJECT_ID)
    @echo "Cleanup complete!"

# List all GCP instances
list-instances PROJECT_ID:
    gcloud compute instances list --project={{PROJECT_ID}}

# List all firewall rules
list-firewalls PROJECT_ID:
    gcloud compute firewall-rules list --project={{PROJECT_ID}}

# Restart container on remote instance
restart-container PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="docker restart sqli-labs-sanitized"

# Stop container on remote instance
stop-container PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="docker stop sqli-labs-sanitized"

# View container logs
container-logs PROJECT_ID:
    gcloud compute ssh sqli-lab --zone=us-central1-a --project={{PROJECT_ID}} --command="docker logs sqli-labs-sanitized"
