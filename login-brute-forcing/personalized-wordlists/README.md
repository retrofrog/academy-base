# Personalized Wordlists

To create a personalized wordlist for the user, we will need to collect some information about them. As our example here is a known public figure, we can check out their [Wikipedia page](https://en.wikipedia.org/wiki/Bill\_Gates) or do a basic Google search to gather the necessary information. Even if this was not a known figure, we can still carry out the same attack and create a personalized wordlist for them. All we need to do is gather some information about them, which is discussed in detail in the [Hashcat](https://academy.hackthebox.com/module/details/20) module, so feel free to check it out.

***

### CUPP

Many tools can create a custom password wordlist based on certain information. The tool we will be using is `cupp`, which is pre-installed in your PwnBox. If we are doing the exercise from our own VM, we can install it with `sudo apt install cupp` or clone it from the [Github repository](https://github.com/Mebus/cupp). `Cupp` is very easy to use. We run it in interactive mode by specifying the `-i` argument, and answer the questions, as follows:

Personalized Wordlists

```shell-session
AIceBear@htb[/htb]$ cupp -i

___________
   cupp.py!                 # Common
      \                     # User
       \   ,__,             # Passwords
        \  (oo)____         # Profiler
           (__)    )\
              ||--|| *      [ Muris Kurgas | j0rgan@remote-exploit.org ]
                            [ Mebus | https://github.com/Mebus/]


[+] Insert the information about the victim to make a dictionary
[+] If you don't know all the info, just hit enter when asked! ;)

> First Name: William
> Surname: Gates
> Nickname: Bill
> Birthdate (DDMMYYYY): 28101955

> Partners) name: Melinda
> Partners) nickname: Ann
> Partners) birthdate (DDMMYYYY): 15081964

> Child's name: Jennifer
> Child's nickname: Jenn
> Child's birthdate (DDMMYYYY): 26041996

> Pet's name: Nila
> Company name: Microsoft

> Do you want to add some key words about the victim? Y/[N]: Phoebe,Rory
> Do you want to add special chars at the end of words? Y/[N]: y
> Do you want to add some random numbers at the end of words? Y/[N]:y
> Leet mode? (i.e. leet = 1337) Y/[N]: y

[+] Now making a dictionary...
[+] Sorting list and removing duplicates...
[+] Saving dictionary to william.txt, counting 43368 words.
[+] Now load your pistolero with william.txt and shoot! Good luck!
```

And as a result, we get our personalized password wordlist saved as `william.txt`.

***

### Password Policy

The personalized password wordlist we generated is about 43,000 lines long. Since we saw the password policy when we logged in, we know that the password must meet the following conditions:

1. 8 characters or longer
2. contains special characters
3. contains numbers

So, we can remove any passwords that do not meet these conditions from our wordlist. Some tools would convert password policies to `Hashcat` or `John` rules, but `hydra` does not support rules for filtering passwords. So, we will simply use the following commands to do that for us:

Code: bash

```bash
sed -ri '/^.{,7}$/d' william.txt            # remove shorter than 8
sed -ri '/[!-/:-@\[-`\{-~]+/!d' william.txt # remove no special chars
sed -ri '/[0-9]+/!d' william.txt            # remove no numbers
```

We see that these commands shortened the wordlist from 43k passwords to around 13k passwords, around 70% shorter.

***

### Mangling

It is still possible to create many permutations of each word in that list. We never know how our target thinks when creating their password, and so our safest option is to add as many alterations and permutations as possible, noting that this will, of course, take much more time to brute force.

Many great tools do word mangling and case permutation quickly and easily, like [rsmangler](https://github.com/digininja/RSMangler) or [The Mentalist](https://github.com/sc0tfree/mentalist.git). These tools have many other options, which can make any small wordlist reach millions of lines long. We should keep these tools in mind because we might need them in other modules and situations.

As a starting point, we will stick to the wordlist we have generated so far and not perform any mangling on it. In case our wordlist does not hit a successful login, we will go back to these tools and perform some mangling to increase our chances of guessing the password.

Tip: The more mangled a wordlist is, the more chances you have to hit a correct password, but it will take longer to brute force. So, always try to be efficient, and properly customize your wordlist using the intelligence you gathered.

***

### Custom Username Wordlist

We should also consider creating a personalized username wordlist based on the person's available details. For example, the person's username could be `b.gates` or `gates` or `bill`, and many other potential variations. There are several methods to create the list of potential usernames, the most basic of which is simply writing it manually.

One such tool we can use is [Username Anarchy](https://github.com/urbanadventurer/username-anarchy), which we can clone from GitHub, as follows:

Personalized Wordlists

```shell-session
AIceBear@htb[/htb]$ git clone https://github.com/urbanadventurer/username-anarchy.git

Cloning into 'username-anarchy'...
remote: Enumerating objects: 386, done.
remote: Total 386 (delta 0), reused 0 (delta 0), pack-reused 386
Receiving objects: 100% (386/386), 16.76 MiB | 5.38 MiB/s, done.
Resolving deltas: 100% (127/127), done.
```

This tool has many use cases that we can take advantage of to create advanced lists of potential usernames. However, for our simple use case, we can simply run it and provide the first/last names as arguments, and forward the output into a file, as follows:

Code: bash

```bash
./username-anarchy Bill Gates > bill.txt
```

We should finally have our username and passwords wordlists ready and we could attack the SSH server.
