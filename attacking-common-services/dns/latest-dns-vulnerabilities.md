# Latest DNS Vulnerabilities

We can find thousands of subdomains and domains on the web. Often they point to no longer active third-party service providers such as AWS, GitHub, and others and, at best, display an error message as confirmation of a deactivated third-party service. Large companies and corporations are also affected time and again. Companies often cancel services from third-party providers but forget to delete the associated DNS records. This is because no additional costs are incurred for a DNS entry. Many well-known bug bounty platforms, such as [HackerOne](https://www.hackerone.com/), already explicitly list `Subdomain Takeover` as a bounty category. With a simple search, we can find several tools on GitHub, for example, that automate the discovery of vulnerable subdomains or help create Proof of Concepts (`PoC`) that can then be submitted to the bug bounty program of our choice or the affected company. RedHuntLabs did a [study](https://redhuntlabs.com/blog/project-resonance-wave-1.html) on this in 2020, and they found that over 400,000 subdomains out of 220 million were vulnerable to subdomain takeover. 62% of them belonged to the e-commerce sector.

**RedHuntLabs Study**

![](https://i0.wp.com/redhuntlabs.com/wp-content/uploads/2020/11/image-3.png) Source: https://redhuntlabs.com/blog/project-resonance-wave-1.html

***

### The Concept of the Attack

One of the biggest dangers of a subdomain takeover is that a phishing campaign can be launched that is considered part of the official domain of the target company. For example, customers would look at the link and see that the domain `customer-drive.inlanefreight.com` (which points to a nonexisting S3 bucket from AWS) is behind the official domain `inlanefreight.com` and trust it as a customer. However, the customers do not know that this page has been mirrored or created by an attacker to provoke a login by the company's customers, for example.

Therefore, if an attacker finds a `CNAME` record in the company's DNS records that points to a subdomain that no longer exists and returns an `HTTP 404 error`, this subdomain can most likely be taken over by us through the use of the third-party provider. A subdomain takeover occurs when a subdomain points to another domain using the CNAME record that does not currently exist. When an attacker registers this nonexistent domain, the subdomain points to the domain registration by us. By making a single DNS change, we make ourselves the owner of that particular subdomain, and after that, we can manage the subdomain as we choose.

**The Concept of Attacks**

![](https://academy.hackthebox.com/storage/modules/116/attack\_concept2.png)

What happens here is that the existing subdomain no longer points to a third-party provider and is therefore no longer occupied by this provider. Pretty much anyone can register this subdomain as their own. Visiting this subdomain and the presence of the CNAME record in the company's DNS leads, in most cases, to things working as expected. However, the design and function of this subdomain are in the hands of the attacker.

**Initiation of Subdomain Takeover**

| **Step** | **Subdomain Takeover**                                                                                                                                                                                     | **Concept of Attacks - Category** |
| -------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `1.`     | The source, in this case, is the subdomain name that is no longer used by the company that we discovered.                                                                                                  | `Source`                          |
| `2.`     | The registration of this subdomain on the third-party provider's site is done by registering and linking to own sources.                                                                                   | `Process`                         |
| `3.`     | Here, the privileges lie with the primary domain owner and its entries in its DNS servers. In most cases, the third-party provider is not responsible for whether this subdomain is accessible via others. | `Privileges`                      |
| `4.`     | The successful registration and linking are done on our server, which is the destination in this case.                                                                                                     | `Destination`                     |

This is when the cycle starts all over again, but this time to trigger the forwarding to the server we control.

**Trigger the Forwarding**

| **Step** | **Subdomain Takeover**                                                                                                                                                                                                                                                        | **Concept of Attacks - Category** |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | The visitor of the subdomain enters the URL in his browser, and the outdated DNS record (CNAME) that has not been removed is used as the source.                                                                                                                              | `Source`                          |
| `6.`     | The DNS server looks in its list to see if it has knowledge about this subdomain and if so, the user is redirected to the corresponding subdomain (which is controlled by us).                                                                                                | `Process`                         |
| `7.`     | The privileges for this already lie with the administrators who manage the domain, as only they are authorized to change the domain and its DNS servers. Since this subdomain is in the list, the DNS server considers the subdomain as trustworthy and forwards the visitor. | `Privileges`                      |
| `8.`     | The destination here is the person who requests the IP address of the subdomain where they want to be forwarded via the network.                                                                                                                                              | `Destination`                     |

Subdomain takeover can be used not only for phishing but also for many other attacks. These include, for example, stealing cookies, cross-site request forgery (CSRF), abusing CORS, and defeating content security policy (CSP). We can see some examples of subdomain takeovers on the [HackerOne website](https://hackerone.com/hacktivity?querystring=%22subdomain%20takeover%22), which have earned the bug bounty hunters considerable payouts.
