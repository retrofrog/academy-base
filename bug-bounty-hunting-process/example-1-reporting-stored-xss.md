# Example 1: Reporting Stored XSS

***

`Title`: Stored Cross-Site Scripting (XSS) in X Admin Panel

`CWE`: [CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')](https://cwe.mitre.org/data/definitions/79.html)

`CVSS 3.1 Score`: 5.5 (Medium)

`Description`: During our testing activities, we identified that the "X for administrators" web application is vulnerable to stored cross-site scripting (XSS) attacks due to inadequate sanitization of user-supplied data. Specifically, the file uploading mechanism at "Admin Info" -> "Secure Data Transfer" -> "Load of Data" utilizes a value obtained from user input, specifically the uploaded file's filename, which is not only directly reflected back to the user’s browser but is also stored into the web application’s database. However, this value does not appear to be adequately sanitized. It, therefore, results in the application being vulnerable to reflected and stored cross-site scripting (XSS) attacks since JavaScript code can be entered in the filename field.

`Impact`: Cross-Site Scripting issues occur when an application uses untrusted data supplied by offensive users in a web browser without sufficient prior validation or escaping. A potential attacker can embed untrusted code within a client-side script to be executed by the browser while interpreting the page. Attackers utilize XSS vulnerabilities to execute scripts in a legitimate user's browser leading to user credentials theft, session hijacking, website defacement, or redirection to malicious sites. Anyone that can send data to the system, including administrators, are possible candidates for performing XSS attacks against the vulnerable application. This issue introduces a significant risk since the vulnerability resides in the "X for administrators” web application, and the uploaded files are visible and accessible by every administrator. Consequently, any administrator can be a possible target of a Cross-Site Scripting attack.

`POC`:

Step 1: A malicious administrator could leverage the fact that the filename value is reflected back to the browser and stored in the web application’s database to perform cross-site scripting attacks against other administrators by uploading a file containing malicious JavaScript code into its filename. The attack is feasible because administrators can view all uploaded files regardless of the uploader. Specifically, we named the file, as follows, using a Linux machine.

Code: javascript

```javascript
"><svg onload = alert(document.cookie)>.docx
```

![image](https://academy.hackthebox.com/storage/modules/161/2.png)

Step 2: When another administrator clicks the view button to open the abovementioned file, the malicious JavaScript code in the file’s filename will be executed on the browser.

![image](https://academy.hackthebox.com/storage/modules/161/3.png) ![image](https://academy.hackthebox.com/storage/modules/161/4.png)

***

### CVSS Score Breakdown

|                        |                                                                                                                         |
| ---------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `Attack Vector:`       | Network - The attack can be mounted over the internet.                                                                  |
| `Attack Complexity:`   | Low - All the attacker (malicious admin) has to do is specify the XSS payload eventually stored in the database.        |
| `Privileges Required:` | High - Only someone with admin-level privileges can access the admin panel.                                             |
| `User Interaction:`    | None - Other admins will be affected simply by browsing a specific (but regularly visited) page within the admin panel. |
| `Scope:`               | Changed - Since the vulnerable component is the webserver and the impacted component is the browser                     |
| `Confidentiality:`     | Low - Access to DOM was possible                                                                                        |
| `Integrity:`           | Low - Through XSS, we can slightly affect the integrity of an application                                               |
| `Availability:`        | None - We cannot deny the service through XSS                                                                           |
