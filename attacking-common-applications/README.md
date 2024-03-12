# Attacking Common Applications

## Introduction to Attacking Common Applications

***

Web-based applications are prevalent in most if not all environments that we encounter as penetration testers. During our assessments, we will come across a wide variety of web applications such as Content Management Systems (CMS), custom web applications, intranet portals used by developers and sysadmins, code repositories, network monitoring tools, ticketing systems, wikis, knowledge bases, issue trackers, servlet container applications, and more. It's common to find the same applications across many different environments. While an application may not be vulnerable in one environment, it may be misconfigured or unpatched in the next. An assessor needs to have a firm grasp of enumerating and attacking the common applications covered in this module.

Web applications are interactive applications that can be accessed via web browsers. Web applications typically adopt a client-server architecture to run and handle interactions. They usually are made up of front-end components (the website interface, or "what the user sees") that run on the client-side (browser) and other back-end components (web application source code) that run on the server-side (back end server/databases). For an in-depth study of the structure and function of web applications, check out the [Introduction to Web Applications](https://academy.hackthebox.com/course/preview/introduction-to-web-applications) module.

All types of web applications (commercial, open-source, and custom) can suffer from the same kinds of vulnerabilities and misconfigurations, namely the top 10 web application risks covered in the [OWASP Top 10](https://owasp.org/www-project-top-ten/). While we may encounter vulnerable versions of many common applications that suffer from known (public) vulnerabilities such as SQL injection, XSS, remote code execution bugs, local file read, and unrestricted file upload, it is equally important for us to understand how we can abuse the built-in functionality of many of these applications to achieve remote code execution.

As organizations continue to harden their external perimeter and limit exposed services, web applications are becoming a more attractive target for malicious actors and penetration testers alike. More and more companies are transitioning to remote work and exposing (intentionally or unintentionally) applications to the outside world. The applications discussed in this module are typically just as likely to be exposed on the external network as the internal network. These applications can serve as a foothold into the internal environment during an external assessment or as a foothold, lateral movement, or additional issue to report to our client during an internal assessment.

[The state of application security in 2021](https://blog.barracuda.com/2021/05/18/report-the-state-of-application-security-in-2021/) was a research survey commissioned by Barracuda to gather information from application security-related decision-makers. The survey includes responses from 750 decision-makers in companies with 500 or more employees across the globe. The survey findings were astounding: 72% of respondents stated that their organization suffered at least one breach due to an application vulnerability, 32% suffered two breaches, and 14% suffered three. The organizations polled broke down their challenges as follows: bot attacks (43%), software supply chain attacks (39%), vulnerability detection (38%), and securing APIs (37%). This module will focus on known vulnerabilities and misconfigurations in open-source and commercial applications (free versions demoed in this module), which make up a large percentage of the successful attacks that organizations face regularly.

***

### Application Data

This module will study several common applications in-depth while briefly covering some other less common (but still seen often) ones. Just some of the categories of applications we may come across during a given assessment that we may be able to leverage to gain a foothold or gain access to sensitive data include:

| **Category**                                                                                                               | **Applications**                                                       |
| -------------------------------------------------------------------------------------------------------------------------- | ---------------------------------------------------------------------- |
| [Web Content Management](https://enlyft.com/tech/web-content-management)                                                   | Joomla, Drupal, WordPress, DotNetNuke, etc.                            |
| [Application Servers](https://enlyft.com/tech/application-servers)                                                         | Apache Tomcat, Phusion Passenger, Oracle WebLogic, IBM WebSphere, etc. |
| [Security Information and Event Management (SIEM)](https://enlyft.com/tech/security-information-and-event-management-siem) | Splunk, Trustwave, LogRhythm, etc.                                     |
| [Network Management](https://enlyft.com/tech/network-management)                                                           | PRTG Network Monitor, ManageEngine Opmanger, etc.                      |
| [IT Management](https://enlyft.com/tech/it-management-software)                                                            | Nagios, Puppet, Zabbix, ManageEngine ServiceDesk Plus, etc.            |
| [Software Frameworks](https://enlyft.com/tech/software-frameworks)                                                         | JBoss, Axis2, etc.                                                     |
| [Customer Service Management](https://enlyft.com/tech/customer-service-management)                                         | osTicket, Zendesk, etc.                                                |
| [Search Engines](https://enlyft.com/tech/search-engines)                                                                   | Elasticsearch, Apache Solr, etc.                                       |
| [Software Configuration Management](https://enlyft.com/tech/software-configuration-management)                             | Atlassian JIRA, GitHub, GitLab, Bugzilla, Bugsnag, Bitbucket, etc.     |
| [Software Development Tools](https://enlyft.com/tech/software-development-tools)                                           | Jenkins, Atlassian Confluence, phpMyAdmin, etc.                        |
| [Enterprise Application Integration](https://enlyft.com/tech/enterprise-application-integration)                           | Oracle Fusion Middleware, BizTalk Server, Apache ActiveMQ, etc.        |

As you can see browsing the links for each category above, there are [thousands of applications](https://enlyft.com/tech/) that we may encounter during a given assessment. Many of these suffer from publicly known exploits or have functionality that can be abused to gain remote code execution, steal credentials, or access sensitive information with or without valid credentials. This module will cover the most prevalent applications that we repeatedly see during internal and external assessments.

Let's take a look at the Enlyft website. We can see, for example, they were able to gather data on over 3.7 million companies that are using [WordPress](https://enlyft.com/tech/products/wordpress) which makes up nearly 70% of the market share worldwide for Web Content Management applications for all companies polled. For SIEM tool [Splunk](https://enlyft.com/tech/products/splunk) was used by 22,174 of the companies surveyed and represented nearly 30% of the market share for SIEM tools. While the remaining applications we will cover represent a much smaller market share for their respective category, I still see these often, and the skills learned here can be applied to many different situations.

While working through the section examples, questions, and skills assessments, make a concerted effort to learn how these applications work and _why_ specific vulnerabilities and misconfigurations exist rather than just reproducing the examples to move swiftly through the module. These skills will benefit you greatly and could likely help you identify attack paths in different applications that you encounter during an assessment for the first time. I still encounter applications that I have only seen a few times or never before, and approaching them with this mindset has often helped me pull off attacks or find a way to abuse built-in functionality.

***

### A Quick Story

For example, during one external penetration test, I encountered the [Nexus Repository OSS application](https://www.sonatype.com/products/repository-oss) from Sonatype, which I had never seen before. I quickly found that the default admin credentials of `admin:admin123` for that version had not been changed, and I was able to log in and poke around the admin functionality. In this version, I leveraged the API as an authenticated user to gain remote code execution on the system. I encountered this application on another assessment, was able to log in with default credentials yet again. This time was able to abuse the [Tasks](https://help.sonatype.com/repomanager3/system-configuration/tasks#Tasks-Admin-Executescript) functionality (which was disabled the first time I encountered this application) and write a quick [Groovy](https://groovy-lang.org/) [script](https://help.sonatype.com/repomanager3/rest-and-integration-api/script-api/writing-scripts) in Java syntax to execute a script and gain remote code execution. This is similar to how we'll abuse the Jenkins [script console](https://www.jenkins.io/doc/book/managing/script-console/) later in this module. I have encountered many other applications, such as [OpManager](https://www.manageengine.com/products/applications\_manager/me-opmanager-monitoring.html) from ManageEngine that allow you to run a script as the user that the application is running under (usually the powerful NT AUTHORITY\SYSTEM account) and gain a foothold. We should never overlook applications during an internal and external assessment as they may be our only way "in" in a relatively well-maintained environment.

***

### Common Applications

I typically run into at least one of the applications below, which we will cover in-depth throughout the module sections. While we cannot cover every possible application that we may encounter, the skills taught in this module will prepare us to approach all applications with a critical eye and assess them for public vulnerabilities and misconfigurations.

| Application          | Description                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                            |
| -------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| WordPress            | [WordPress](https://wordpress.org/) is an open-source Content Management System (CMS) that can be used for multiple purposes. It's often used to host blogs and forums. WordPress is highly customizable as well as SEO friendly, which makes it popular among companies. However, its customizability and extensible nature make it prone to vulnerabilities through third-party themes and plugins. WordPress is written in PHP and usually runs on Apache with MySQL as the backend.                                                                                                                                                                                                                                |
| Drupal               | [Drupal](https://www.drupal.org/) is another open-source CMS that is popular among companies and developers. Drupal is written in PHP and supports using MySQL or PostgreSQL for the backend. Additionally, SQLite can be used if there's no DBMS installed. Like WordPress, Drupal allows users to enhance their websites through the use of themes and modules.                                                                                                                                                                                                                                                                                                                                                      |
| Joomla               | [Joomla](https://www.joomla.org/) is yet another open-source CMS written in PHP that typically uses MySQL but can be made to run with PostgreSQL or SQLite. Joomla can be used for blogs, discussion forums, e-commerce, and more. Joomla can be customized heavily with themes and extensions and is estimated to be the third most used CMS on the internet after WordPress and Shopify.                                                                                                                                                                                                                                                                                                                             |
| Tomcat               | [Apache Tomcat](https://tomcat.apache.org/) is an open-source web server that hosts applications written in Java. Tomcat was initially designed to run Java Servlets and Java Server Pages (JSP) scripts. However, its popularity increased with Java-based frameworks and is now widely used by frameworks such as Spring and tools such as Gradle.                                                                                                                                                                                                                                                                                                                                                                   |
| Jenkins              | [Jenkins](https://jenkins.io/) is an open-source automation server written in Java that helps developers build and test their software projects continuously. It is a server-based system that runs in servlet containers such as Tomcat. Over the years, researchers have uncovered various vulnerabilities in Jenkins, including some that allow for remote code execution without requiring authentication.                                                                                                                                                                                                                                                                                                         |
| Splunk               | Splunk is a log analytics tool used to gather, analyze and visualize data. Though not originally intended to be a SIEM tool, Splunk is often used for security monitoring and business analytics. Splunk deployments are often used to house sensitive data and could provide a wealth of information for an attacker if compromised. Historically, Splunk has not suffered from a considerable amount of known vulnerabilities aside from an information disclosure vulnerability ([CVE-2018-11409](https://nvd.nist.gov/vuln/detail/CVE-2018-11409)), and an authenticated remote code execution vulnerability in very old versions ([CVE-2011-4642](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2011-4642)). |
| PRTG Network Monitor | [PRTG Network Monitor](https://www.paessler.com/prtg) is an agentless network monitoring system that can be used to monitor metrics such as uptime, bandwidth usage, and more from a variety of devices such as routers, switches, servers, etc. It utilizes an auto-discovery mode to scan a network and then leverages protocols such as ICMP, WMI, SNMP, and NetFlow to communicate with and gather data from discovered devices. PRTG is written in [Delphi](https://en.wikipedia.org/wiki/Delphi\_\(software\)).                                                                                                                                                                                                  |
| osTicket             | [osTicket](https://osticket.com/) is a widely-used open-source support ticketing system. It can be used to manage customer service tickets received via email, phone, and the web interface. osTicket is written in PHP and can run on Apache or IIS with MySQL as the backend.                                                                                                                                                                                                                                                                                                                                                                                                                                        |
| GitLab               | [GitLab](https://about.gitlab.com/) is an open-source software development platform with a Git repository manager, version control, issue tracking, code review, continuous integration and deployment, and more. It was originally written in Ruby but now utilizes Ruby on Rails, Go, and Vue.js. GitLab offers both community (free) and enterprises versions of the software.                                                                                                                                                                                                                                                                                                                                      |

***

### Module Targets

Throughout the module sections, we will refer to URLs such as `http://app.inlanefreight.local`. To simulate a large, realistic environment with multiple webservers, we utilize Vhosts to house the web applications. Since these Vhosts all map to a different directory on the same host, we have to make manual entries in our `/etc/hosts` file on the Pwnbox or local attack VM to interact with the lab. This needs to be done for any examples that show scans or screenshots using a FQDN. Sections such as Splunk that only use the spawned target's IP address will not require a hosts file entry, and you can just interact with the spawned IP address and associated port.

To do this quickly, we could run the following:

Introduction to Attacking Common Applications

```shell-session
AIceBear@htb[/htb]$ IP=10.129.42.195
AIceBear@htb[/htb]$ printf "%s\t%s\n\n" "$IP" "app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local" | sudo tee -a /etc/hosts
```

After this command, our `/etc/hosts` file would look like the following (on a newly spawned Pwnbox):

Introduction to Attacking Common Applications

```shell-session
AIceBear@htb[/htb]$ cat /etc/hosts

# Your system has configured 'manage_etc_hosts' as True.
# As a result, if you wish for changes to this file to persist
# then you will need to either
# a.) make changes to the master file in /etc/cloud/templates/hosts.debian.tmpl
# b.) change or remove the value of 'manage_etc_hosts' in
#     /etc/cloud/cloud.cfg or cloud-config from user-data
#
127.0.1.1 htb-9zftpkslke.htb-cloud.com htb-9zftpkslke
127.0.0.1 localhost

# The following lines are desirable for IPv6 capable hosts
::1 ip6-localhost ip6-loopback
fe00::0 ip6-localnet
ff00::0 ip6-mcastprefix
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
ff02::3 ip6-allhosts

10.129.42.195	app.inlanefreight.local dev.inlanefreight.local blog.inlanefreight.local
```

You may wish to write your own script or edit the hosts file by hand, which is fine.

If you spawn a target during a section and cannot access it directly via the IP be sure to check your hosts file and update any entries!

Module exercises that require vhosts will display a list that you can use to edit your hosts file after spawning the target VM at the bottom of the respective section.
