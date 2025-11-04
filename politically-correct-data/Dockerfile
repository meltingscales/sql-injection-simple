FROM ubuntu:14.04

# Install Apache, PHP, and MySQL
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    apache2 \
    php5 \
    php5-mysql \
    mysql-server \
    git \
    && apt-get clean

# Clone SQLi-Labs
RUN git clone https://github.com/Audi-1/sqli-labs.git /var/www/html/sqli-labs

# Copy sanitized database and query logger
COPY security.sql /tmp/security.sql
COPY show-queries.php /var/www/html/sqli-labs/show-queries.php

# Configure Apache for port 8080 (Cloud Run requirement)
RUN sed -i 's/DocumentRoot \/var\/www\/html/DocumentRoot \/var\/www\/html\/sqli-labs/' /etc/apache2/sites-available/000-default.conf && \
    sed -i 's/Listen 80/Listen 8080/' /etc/apache2/ports.conf && \
    sed -i 's/:80/:8080/' /etc/apache2/sites-available/000-default.conf && \
    echo "ServerName localhost" >> /etc/apache2/apache2.conf && \
    sed -i 's|ErrorLog.*|ErrorLog /dev/stderr|' /etc/apache2/apache2.conf && \
    sed -i 's|CustomLog.*|CustomLog /dev/stdout combined|' /etc/apache2/sites-available/000-default.conf

# Setup startup script
COPY run.sh /run.sh
RUN chmod +x /run.sh

EXPOSE 8080

CMD ["/run.sh"]
