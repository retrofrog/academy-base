# Regular Expression Denial of Service (ReDoS)

Suppose we have a user that submits benign input to an API. On the server side, a developer could match any input against a regular expression. After a usually constant amount of time, the API responds. In some instances, an attacker may be able to cause significant delays in the API's response time by submitting a crafted payload that tries to exploit some particularities/inefficiencies of the regular expression matching engine. The longer this crafted payload is, the longer the API will take to respond. Exploiting such "evil" patterns in a regular expression to increase evaluation time is called a Regular Expression Denial of Service (ReDoS) attack.

Let us assess an API that is vulnerable to ReDoS attacks together.

Proceed to the end of this section and click on `Click here to spawn the target system!` or the `Reset Target` icon. Use the provided Pwnbox or a local VM with the supplied VPN key to reach the target application and follow along.

The API resides in `http://<TARGET IP>:3000/api/check-email` and accepts a parameter called _email_.

Let's interact with it as follows.

Regular Expression Denial of Service (ReDoS)

```shell-session
AIceBear@htb[/htb]$ curl "http://<TARGET IP>:3000/api/check-email?email=test_value"
{"regex":"/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/","success":false}
```

Submit the above regex to [regex101.com](https://regex101.com/) for an in-depth explanation. Then, submit the above regex to [https://jex.im/regulex/](https://jex.im/regulex/#!flags=\&re=%5E\(%5Ba-zA-Z0-9\_.-%5D\)%2B%40\(\(%5Ba-zA-Z0-9-%5D\)%2B.\)%2B\(%5Ba-zA-Z0-9%5D%7B2%2C4%7D\)%2B%24) for a visualization.

![image](https://academy.hackthebox.com/storage/modules/160/TXFOUkOko.png)

The second and third groups are doing bad iterative checks.

Let's submit the following valid value and see how long the API takes to respond.

Regular Expression Denial of Service (ReDoS)

```shell-session
AIceBear@htb[/htb]$ curl "http://<TARGET IP>:3000/api/check-email?email=jjjjjjjjjjjjjjjjjjjjjjjjjjjj@ccccccccccccccccccccccccccccc.55555555555555555555555555555555555555555555555555555555."
{"regex":"/^([a-zA-Z0-9_.-])+@(([a-zA-Z0-9-])+.)+([a-zA-Z0-9]{2,4})+$/","success":false}
```

You will notice that the API takes several seconds to respond and that longer payloads increase the evaluation time.

The difference in response time between the first cURL command above and the second is significant.

The API is undoubtedly vulnerable to ReDoS attacks.

**Questions**

There are more than one payload lengths to exploit/trigger the ReDoS vulnerability. Answer format: Yes, No

```bash
Yes
```
