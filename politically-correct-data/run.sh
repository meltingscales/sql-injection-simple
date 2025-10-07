#!/bin/bash

# Start MySQL
service mysql start

# Wait for MySQL to be ready
sleep 5

# Create database and import sanitized data
mysql -u root -e "CREATE DATABASE IF NOT EXISTS security;"
mysql -u root security < /tmp/security.sql

# Update database credentials in SQLi-Labs
cat > /var/www/html/sqli-labs/sql-connections/db-creds.inc <<EOF
<?php
\$dbuser ='root';
\$dbpass ='';
\$dbname ="security";
\$host = 'localhost';
\$dbname1 = "challenges";
?>
EOF

# Start Apache in foreground
apachectl -D FOREGROUND
