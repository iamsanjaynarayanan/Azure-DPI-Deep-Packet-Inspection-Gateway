#!/usr/bin/env bash

# Set your Azure VM Gateway Public IP
GATEWAY_IP="20.219.207.32"
GATEWAY_PORT="8080"
TARGET_URL="http://${GATEWAY_IP}:${GATEWAY_PORT}"

echo "=================================================="
echo " Starting Azure DPI Engine Security Test"
echo " Target: ${TARGET_URL}"
echo "=================================================="
echo ""

# ------------------------------------------------------------------------------
# 1. CLEAN TRAFFIC TEST
# Expected Behavior: Forwarded to Backend VM (HTTP 200 OK)
# ------------------------------------------------------------------------------
echo "[TEST 1] Sending Legitimate HTTP Request..."
curl.exe -i "${TARGET_URL}/"
echo -e "\n\n"

# ------------------------------------------------------------------------------
# 2. SQL INJECTION (SQLi) ATTACK PAYLOADS
# Expected Behavior: Blocked by DPI Engine (HTTP 403 Forbidden)
# Signature: Regex matching `' OR '1'='1`, `UNION SELECT`, `DROP TABLE`
# ------------------------------------------------------------------------------

# Test 2a: Standard OR-based Authentication Bypass
echo "[TEST 2a] SQLi Payload: Tautology (' OR '1'='1)..."
curl.exe -i "${TARGET_URL}/?id=1' OR '1'='1"
echo -e "\n\n"

# Test 2b: URL-encoded SQLi Payload
# Decodes to: ?id=1' OR '1'='1
echo "[TEST 2b] SQLi Payload: URL-Encoded Query Parameter..."
curl.exe -G --data-urlencode "id=1' OR '1'='1" "${TARGET_URL}/"
echo -e "\n\n"

# Test 2c: Union-Based Data Exfiltration
echo "[TEST 2c] SQLi Payload: UNION SELECT Query..."
curl.exe -i "${TARGET_URL}/?search=1 UNION SELECT username, password FROM users"
echo -e "\n\n"

# Test 2d: Destructive DDL Injection
echo "[TEST 2d] SQLi Payload: DROP TABLE Command..."
curl.exe -i "${TARGET_URL}/?item=1; DROP TABLE users--"
echo -e "\n\n"

# ------------------------------------------------------------------------------
# 3. CROSS-SITE SCRIPTING (XSS) ATTACK PAYLOADS
# Expected Behavior: Blocked by DPI Engine (HTTP 403 Forbidden)
# Signature: Regex matching `<script>`, `javascript:`, `onerror=`, `<iframe>`
# ------------------------------------------------------------------------------

# Test 3a: Basic Script Injection
echo "[TEST 3a] XSS Payload: Inline <script> tag..."
curl.exe -i "${TARGET_URL}/?comment=<script>alert('XSS')</script>"
echo -e "\n\n"

# Test 3b: Event Handler Injection
echo "[TEST 3b] XSS Payload: Inline Image Event Handler (onerror)..."
curl.exe -i "${TARGET_URL}/?user=<img src=x onerror=alert(1)>"
echo -e "\n\n"

# Test 3c: Iframe Injection
echo "[TEST 3c] XSS Payload: Hidden Iframe Tag..."
curl.exe -i "${TARGET_URL}/?page=<iframe src='http://malicious.com'></iframe>"
echo -e "\n\n"

# ------------------------------------------------------------------------------
# 4. RECONNAISSANCE & SCANNER USER-AGENT DETECTION
# Expected Behavior: Blocked by DPI Engine (HTTP 403 Forbidden)
# Signature: Regex matching scanners like `sqlmap`, `nikto`, `nmap`, `gobuster`
# ------------------------------------------------------------------------------

# Test 4a: Automated SQLi Scanner Probe
echo "[TEST 4a] Scanner Detection: sqlmap User-Agent..."
curl.exe -i -A "sqlmap/1.5.2#stable" "${TARGET_URL}/"
echo -e "\n\n"

# Test 4b: Web Server Vulnerability Scanner Probe
echo "[TEST 4b] Scanner Detection: Nikto Web Scanner User-Agent..."
curl.exe -i -A "Mozilla/5.0 (Nikto/2.1.6)" "${TARGET_URL}/"
echo -e "\n\n"

# ------------------------------------------------------------------------------
# 5. RATE-LIMITING STRESS TEST (DoS Protection)
# Expected Behavior: First 9 requests return 200/403, 10th+ requests within 
# 10 seconds return HTTP 429 Too Many Requests
# Rule: Maximum 10 requests per 10-second sliding window
# ------------------------------------------------------------------------------
echo "[TEST 5] Rate-Limiting Verification: Rapid-fire 12 requests..."
for i in {1..12}; do
    echo -n "Request #${i}: "
    curl.exe -s -o /dev/null -w "%{http_code}\n" "${TARGET_URL}/"
done

echo ""
echo "=================================================="
echo " Test Execution Finished"
echo "=================================================="