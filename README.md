# SQL Injection Training Lab

A SQL injection training environment deployed on Google Cloud Run with automatic `*.run.app` domain.

## Quick Start

Deploy to Cloud Run:

```bash
just deploy YOUR_PROJECT_ID
```

This will build and deploy the lab, giving you a URL like `https://sqli-lab-xxxxx-uc.a.run.app`

## Available Commands

```bash
just deploy PROJECT_ID      # Deploy to Cloud Run
just get-url PROJECT_ID     # Get your service URL
just logs PROJECT_ID        # View logs
just logs-follow PROJECT_ID # Follow logs in real-time
just test PROJECT_ID        # Test the deployment
just delete PROJECT_ID      # Delete the service
```

## Benefits

- **No IP blocking**: Gets automatic `*.run.app` domain
- **Cost effective**: Only pay when handling requests (likely free tier)
- **Auto-scaling**: Scales to zero when idle
- **No infrastructure**: No VMs to manage

## Resources

- [PHP SQL Injection Security](https://www.php.net/manual/en/security.database.sql-injection.php)
- [PHP Prepared Statements](https://www.php.net/manual/en/mysqli.quickstart.prepared-statements.php)
