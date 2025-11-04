#!/bin/bash
set -e

echo "Initializing MySQL data directory..."
mkdir -p /var/run/mysqld
chown mysql:mysql /var/run/mysqld

echo "Starting MySQL directly..."
# Start MySQL in background without service wrapper
/usr/sbin/mysqld --user=mysql --skip-grant-tables &
MYSQL_PID=$!

# Wait for MySQL to be ready with better check
echo "Waiting for MySQL to be ready..."
for i in {1..30}; do
    if mysqladmin ping &>/dev/null; then
        echo "MySQL is ready!"
        break
    fi
    echo "Waiting for MySQL... attempt $i/30"
    sleep 1
done

if ! mysqladmin ping &>/dev/null; then
    echo "MySQL failed to start!"
    exit 1
fi

echo "Creating database and importing sanitized data..."
mysql -u root -e "DROP DATABASE IF EXISTS security;"
mysql -u root -e "CREATE DATABASE security;"
mysql -u root security < /tmp/security.sql
echo "Database setup complete!"

echo "Removing setup page to prevent data reset..."
rm -f /var/www/html/sqli-labs/sql-connections/setup-db.php
rm -f /var/www/html/sqli-labs/sql-connections/setup-db-challenge.php

echo "Configuring database credentials..."
cat > /var/www/html/sqli-labs/sql-connections/db-creds.inc <<EOF
<?php
\$dbuser ='root';
\$dbpass ='';
\$dbname ="security";
\$host = 'localhost';
\$dbname1 = "challenges";
?>
EOF

echo "Starting Apache on port 8080..."
# Start Apache in foreground
exec apachectl -D FOREGROUND
