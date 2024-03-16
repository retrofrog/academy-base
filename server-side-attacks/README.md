# Server-side Attacks

## Introduction to Server-Side Attacks

***

Server-Side attacks target the application or service provided by a server, whereas the purpose of a client-side attack is to attack the client. Understanding and identifying the differences is essential for penetration testing and bug bounty hunting.

An excellent example of these that should help clarify the differences between server-side attacks vs. client-side attacks are `Cross-Site Request Forgeries (CSRF)` and `Server-side Request Forgeries (SSRF)`. Both of these attacks involve a web server and how servers process URLs. However, CSRF and SSRF have different targets and purposes.

Roughly quoted from the Cross-Site Request Forgery section in the [Introduction to Web Applications](https://academy.hackthebox.com/course/preview/introduction-to-web-applications) module:

CSRF attacks may utilize other client side -attacks like XSS vulnerabilities to perform requests to a web application that a victim has already been authenticated to. This allows the attacker to perform actions as the authorized user, such as changing their password to something the attacker would know or performing any unwarranted action as the victim.

From the above situation, we should be able to infer that the target is the client. Server-Side attacks target the actual application, the objective being to leak sensitive data or inject unwarranted input into the application and even achieve remote code execution (RCE). The targets in this situation are the back-end services.

***

### Types of Server-Side Attacks

This module will cover different types of Server-Side attacks and how to exploit them. These are:

* `Abusing Intermediary Applications`: Accessing internal applications not accessible from our network by leveraging specific exposed binary protocols.
* `Server-Side Request Forgery (SSRF)`: Making the hosting application server issue requests to arbitrary external domains or internal resources in an attempt to identify sensitive data.
* `Server-Side Includes Injection (SSI)`: Injecting a payload so that ill-intended Server-Side Include directives are parsed to achieve remote code execution or leak sensitive data. This vulnerability occurs when poorly validated user input manages to become part of a response that is parsed for Server-Side Include directives.
* `Edge-Side Includes Injection (ESI)`: ESI is an XML-based markup language used to tackle performance issues by temporarily storing dynamic web content that the regular web caching protocols do not save. Edge-Side Include Injection occurs when an attacker manages to reflect ill-intended ESI tags in the HTTP Response. The root cause of this vulnerability is that HTTP surrogates cannot validate the ESI tag origin. They will gladly parse and evaluate legitimate ESI tags by the upstream server and malicious ESI tags supplied by an attacker.
* `Server-Side Template Injection (SSTI)`: Template Engines facilitate dynamic data presentation through web pages or emails. Server-Side Template Injection is essentially injecting ill-intended template directives (payload) inside a template, leveraging Template Engines that insecurely mix user input with a given template.
* `Extensible Stylesheet Language Transformations Server-Side Injection (XSLT)`: XSLT is an XML-based language usually used when transforming XML documents into HTML, another XML document, or PDF. Extensible Stylesheet Language Transformations Server-Side Injection can occur when arbitrary XSLT file upload is possible or when an application generates the XSL Transformation’s XML document dynamically using unvalidated input from the user.

***

### Moving On

Let's now dive into each attack in detail.
