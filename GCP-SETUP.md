# SQLi-Labs GCP Deployment Guide

## Quick Setup (5 minutes)

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

### 3. SSH into Instance and Deploy Container

```bash
gcloud compute ssh sqli-lab --zone=us-central1-a
```

Once connected:

```bash
docker run -d -p 80:80 --name sqli-labs acgpiano/sqli-labs
```

### 4. Get External IP

```bash
gcloud compute instances describe sqli-lab \
  --zone=us-central1-a \
  --format='get(networkInterfaces[0].accessConfigs[0].natIP)'
```

### 5. Test from PowerShell

```powershell
$ip = "YOUR_EXTERNAL_IP"
Invoke-WebRequest "http://$ip/Less-1/"
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
