# Beyond this Module

### Real World

As a Penetration Tester, one could expect the tasks undertaken in this module to be everyday tasks assigned to us during our day-to-day duties. Sometimes under direct guidance and supervision, sometimes not depending on our skill level. Having a deep understanding of `Pivoting`, `Tunneling`, `Port Forwarding`, `Lateral Movement` and the `tools/techniques` needed to perform these actions is essential for accomplishing our mission. Our actions can and probably will often influence the actions of our teammates and more senior testers since they may be basing their next steps on our results if we are working jointly on an assessment.

Those actions could include:

* Utilizing tunnels and pivot points we set up to perform additional `exploitation` and `lateral movement`.
* Implanting `persistence` mechanisms in each subnet to ensure continued access.
* `Command & Control` inside and throughout enterprise environments.
* Utilizing our tunnels for `security control bypass` when bringing tools in and exfiltrating data.

Having a firm grasp of networking concepts and how pivoting and tunneling functions is a core skill for any pentester or defender. If any of the concepts, terminology, or actions discussed in this module were a bit challenging or confusing, consider going back and checking out the [Introduction to Networking](https://academy.hackthebox.com/course/preview/introduction-to-networking) module. It provides us with a solid foundation in Networking concepts such as subnetting, layer 2-3 technologies, tools, and common addressing mechanisms.

***

### What's Next?

To better understand Active Directory and how to use our new skills in enterprise pentesting, check out the [Introduction to Active Directory](https://academy.hackthebox.com/course/preview/introduction-to-active-directory) and [Active Directory Enumeration and Attacks](https://academy.hackthebox.com/course/preview/active-directory-enumeration--attacks) module. The [Shells and Payloads](https://academy.hackthebox.com/course/preview/shells--payloads) module can help us improve our exploitation skills and give us better insight into the payloads we create and use in a target network. If the webserver shells and pivots portions in this module were difficult, checking out the [Introduction to Web Applications](https://academy.hackthebox.com/course/preview/introduction-to-web-applications) and [File Upload Attacks](https://academy.hackthebox.com/course/preview/file-upload-attacks) modules can clarify those topics for us. Don't discount the fantastic challenge that [Starting Point](https://app.hackthebox.com/starting-point) is. These can be great ways to practice applying the skills you learn in this module and other modules on Academy to challenges on Hack The Box's main platform.

![Scrolling Through Starting Point](https://academy.hackthebox.com/storage/modules/158/startingpoint.gif)

***

### Pivoting & Tunneling Into Other Learning Opportunities

The Hack The Box main platform has many targets for learning and practicing the skills learned in this module. The [Containers and Pivoting](https://app.hackthebox.com/tracks/Containers-and-Pivoting) track can provide you with a real challenge to put your pivoting skills to the test. `Tracks` are curated lists of machines and challenges for users to work through and master a particular topic. Each track contains boxes of varying difficulties with various attack vectors. Even if you cannot solve these boxes on your own, it is still worth working with them with a walkthrough or video or just watching a video on the box by Ippsec. The more you expose yourself to these topics, the more comfortable you will become. The boxes below are great for practicing the skills learned in this module.

***

**Boxes To Pwn**

* [Enterprise](https://app.hackthebox.com/machines/Enterprise) [IPPSec Walkthrough](https://youtube.com/watch?v=NWVJ2b0D1r8\&t=2400)
* [Inception](https://app.hackthebox.com/machines/Inception) [IPPSec Walkthrough](https://youtube.com/watch?v=J2I-5xPgyXk\&t=2330)
* [Reddish](https://app.hackthebox.com/machines/Reddish) [IPPSec Walkthrough](https://youtube.com/watch?v=Yp4oxoQIBAM\&t=2466) This host is quite a challenge.

![Scrolling Through HTB Boxes](https://academy.hackthebox.com/storage/modules/158/htbboxes.gif)

Ippsec has recorded videos explaining the paths through many of these boxes. As a resource, [Ippsec's site](https://ippsec.rocks/?) is a great resource to search for videos and write-ups pertaining to many different subjects. Check out his videos and write-ups if you get stuck or want a great primer dealing with Active Directory and wish to see how some of the tools work.

***

**ProLabs**

`Pro Labs` are large simulated corporate networks that teach skills applicable to real-life penetration testing engagements. The `Dante` Pro Lab is an excellent place to practice chaining our pivoting skills together with other enterprise attack knowledge. The `Offshore` and `RastaLabs` Pro Labs are intermediate-level labs that contain a wealth of opportunities for practicing pivoting through networks.

* [RastaLabs](https://app.hackthebox.com/prolabs/overview/rastalabs) Pro Lab
* [Dante](https://app.hackthebox.com/prolabs/overview/dante) Pro Lab
* [Offshore](https://app.hackthebox.com/prolabs/overview/offshore) Pro Lab

Head [HERE](https://app.hackthebox.com/prolabs) to check out all the Pro Labs that HTB has to offer.

***

**Endgames**

For an extreme challenge that may take you a while to get through, check out the [Ascension](https://app.hackthebox.com/endgames/ascension) Endgames. This endgame features two different AD domains and has plenty of chances to practice our AD enumeration and attacking skills.

![text](https://academy.hackthebox.com/storage/modules/143/endgame.png)

***

**Writers/Educational Creators and Blogs To Follow**

Between the HTB `Discord`, `Forums`, and `blogs`, there are plenty of outstanding write-ups to help advance your skills along the way. One to pay attention to would be [0xdf's walkthroughs](https://0xdf.gitlab.io/). His blog is a great resource to help us understand how the tools, tactics, and concepts we are learning tie together into a holistic attack path. The list below contains links to other authors and blogs we feel do a great job discussing Information Security topics.

[RastaMouse](https://rastamouse.me/) writes excellent content on Red-Teaming, C2 infrastructure, pivoting, payloads, etc. (He even made a Pro Lab to showcase those things!)

[SpecterOps](https://posts.specterops.io/offensive-security-guide-to-ssh-tunnels-and-proxies-b525cbd4d4c6) has written a great post covering SSH Tunneling and the use of proxies over a multitude of protocols. It's a must-read for anyone looking to know more about the subject and would make a handy resource to have during an engagement.

The [HTB Blog](https://www.hackthebox.com/blog) is, of course, a great place to read up on current threats, how-to's for popular TTPs, and more.

[SANS](https://www.sans.org/webcasts/dodge-duck-dip-dive-dodge-making-the-pivot-cheat-sheet-119115/) puts out plenty of great infosec related information and webcasts like the one linked here are a great example of that. This will cover many different Pivoting tools and avenues of use.

[Plaintext's Pivoting Workshop](https://youtu.be/B3GxYyGFYmQ) is an incredible workshop that our very own Academy Training Developer, Plaintext, put together to help prepare players for Cyber Apocalypse CTF 2022. The workshop is delivered in an engaging & entertaining manner, and viewers will benefit from it for years to come. Check it out if you get the chance.

***

### Closing Thoughts

Congratulations on completing this module, and we at HTB know you have learned some new skills to use during your journey into the world of Cyber Security. `Pivoting, Tunneling, and Port Forwarding` are foundational concepts that should be in every pentesters toolbox.

As a defender, knowing how to spot when a host is compromised and being used as a pivot point or if traffic is being tunneled through a non-standard route is crucial. Keep practicing and leveling up your skillset. Happy Hacking!
