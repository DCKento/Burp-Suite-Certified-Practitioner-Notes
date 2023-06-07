# Vuln Entry Points

## Stage 1: Gaining access to a user

### List of possible vulns and the ‘hooks’ for exploitation:

- XSS
    - search box
        - note the different labs this could be, including custom tag and some tags allowed
    - storeId parameter into location.search
    - ng-app
    - searchResults.js file with JSON response and eval() function
    - loadCommentsWithVulnerableEscapeHtml.js JavaScript function replace() to encode angle brackets.
    - onclick event handler attribute
    - JavaScript template string
- CSRF
    - Change email function
    - Websocket hijacking via live chat
    - OAuth flow with no SameSite restrictions
- Clickjacking
    - Change email myaccount
- DOM-Based
    - addEventListener() that listens for web messages
    - event listener that uses JSON.parse() and postMessage()
    - client side cookie lastViewedProduct. onload event handler
    - location.href
- CORS
    - Access-Control-Allow-Credentials
    - Access-Control-Allow-Origin
- HTTP Request Smuggling
    - Test for request smuggling on home page using HTTP Request Smuggler extension and Active Scan
- Access Control
    - roleid
    - myaccount
    - anything role related
- Authentication
    - username enumeration and password brute force
    - Stay logged in cookie
    - password reset functionality
- Web Cache Poisoning
    - /resources/js/tracking.js
    - `X-Forwarded-Scheme`
    - callback (/js/geolocate.js)
    - setCountryCookie
- HTTP Host Header Attacks
    - temp-forgot-password-token
    - /resources/js/tracking.js
    - Collaborator interaction
- OAuth
    - anything OAuth related
    - Social Media linkage
- JWT
    - Anything JWT related

## Stage 2: Gaining access to admin

### List of possible vulns and the ‘hooks’ for exploitation:

SQL Injection:

- Products, Category, Released
    - Stock Checker
- TrackingId Cookie

XSS

- search box
    - note the different labs this could be, including custom tag and some tags allowed
- storeId parameter into location.search
- ng-app
- searchResults.js file with JSON response and eval() function
- loadCommentsWithVulnerableEscapeHtml.js JavaScript function replace() to encode angle brackets.
- onclick event handler attribute
- JavaScript template string

CSRF

- Change email function
- Websocket hijacking via live chat
- OAuth flow with no SameSite restrictions

Clickjacking

- Change email myaccount

DOM-Based

- addEventListener() that listens for web messages
- event listener that uses JSON.parse() and postMessage()
- client side cookie lastViewedProduct. onload event handler
- location.href

CORS

- Access-Control-Allow-Credentials
- Access-Control-Allow-Origin

HTTP Request Smuggling

- Test for request smuggling on home page using HTTP Request Smuggler extension and Active Scan

Access Control

- roleid
- myaccount
- anything role related

Authentication

- username enumeration and password brute force
- Stay logged in cookie
- password reset functionality

Web Cache Poisoning

- /resources/js/tracking.js
- `X-Forwarded-Scheme`
- callback (/js/geolocate.js)
- setCountryCookie

HTTP Host Header Attacks

- temp-forgot-password-token
- /resources/js/tracking.js
- Collaborator interaction

OAuth

- anything OAuth related
- Social Media linkage

JWT

- Anything JWT related

## Stage 3: Data Exfiltration

### List of possible vulns and the ‘hooks’ for exploitation:

SQL Injection:

- Products, Category, Released
    - Stock Checker
- TrackingId Cookie

XXE

- stockCheck

SSRF

- StockApi
- path parameter

OS Command Injection

- productId
- store ID
- email

SSTI

- /message?=Out of stock
- my-account/change-blog-post-author-display

Directory Traversal

- /image?filename=x.jpg

Insecure Deserialisation

- session cookie URL and base64 encoded
- /libs/customTemplate.php

File Upload Vulns

- If you’re able to upload files
