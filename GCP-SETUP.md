# SQLi-Labs GCP Deployment Guide

This guide deploys a sanitized version of SQLi-Labs with appropriate test data (no offensive usernames/passwords).

## Quick Setup (10 minutes)

### 1. Create GCP Compute Engine Instance

```bash
gcloud compute instances create sqli-lab \
  --project=YOUR_PROJECT_ID \
  --zone=us-central1-a \
  --machine-type=e2-micro \
  --image-family=cos-stable \
  --image-project=cos-cloud \
  --boot-disk-size=10GB \
  --tags=http-server,https-server
```

### 2. Create Firewall Rule

```bash
gcloud compute firewall-rules create allow-http-sqli \
  --project=YOUR_PROJECT_ID \
  --allow=tcp:80 \
  --target-tags=http-server
```

### 3. Copy Files and Build Container

Copy the sanitized container files to the GCP instance:

```bash
gcloud compute scp --zone=us-central1-a --recurse politically-correct-data sqli-lab:~/
```

SSH into the instance:

```bash
gcloud compute ssh sqli-lab --zone=us-central1-a
```

Build and run the container:

```bash
cd politically-correct-data
docker build -t sqli-labs-sanitized .
docker run -d -p 80:80 --name sqli-labs-sanitized sqli-labs-sanitized
```

### 4. Fix Container-Optimized OS Firewall

Container-Optimized OS has iptables rules that block external traffic. Add a rule to allow port 80:

```bash
sudo iptables -I INPUT 1 -p tcp --dport 80 -j ACCEPT
```

Exit the SSH session:

```bash
exit
```

### 5. Get External IP

```bash
gcloud compute instances describe sqli-lab \
  --zone=us-central1-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

### 6. Test from PowerShell

```powershell
$ip = "YOUR_EXTERNAL_IP"
Invoke-WebRequest "http://$ip/Less-1/"
```

## Sanitized Data

The database has been updated with appropriate test data:

| ID | Username | Password |
|----|----------|----------|
| 1  | alice    | password123 |
| 2  | angelina | secret456 |
| 3  | bob      | p@ssword |
| 4  | secure   | securepass |
| 5  | charlie  | charlie789 |
| 6  | superman | krypton |
| 7  | batman   | gotham |
| 8+ | admin*   | admin* |

## Viewing Logs

Apache access logs are available in the container:

```bash
# View recent logs
gcloud compute ssh sqli-lab --zone=us-central1-a --command="docker exec sqli-labs-sanitized tail -20 /var/log/apache2/access.log"

# Follow logs in real-time
gcloud compute ssh sqli-lab --zone=us-central1-a --command="docker exec sqli-labs-sanitized tail -f /var/log/apache2/access.log"

# View detailed logs (with response times)
gcloud compute ssh sqli-lab --zone=us-central1-a --command="docker exec sqli-labs-sanitized tail -20 /var/log/apache2/detailed_access.log"
```

Or use the provided script:

```bash
./view-logs.sh
```

## Available Labs

- **Less-1 to Less-65**: Different SQL injection types
- **GET-based**: Less-1 to Less-4, Less-8 to Less-14
- **POST-based**: Less-5, Less-6, Less-11
- **Blind**: Less-8 onwards
- **Error-based**: Less-1 to Less-4

## Clean Up

```bash
gcloud compute instances delete sqli-lab --zone=us-central1-a
gcloud compute firewall-rules delete allow-http-sqli
```

## Cost Estimate

- e2-micro: ~$6/month (730 hours)
- Egress: Minimal for lab use
- **Remember to delete when not in use!**
