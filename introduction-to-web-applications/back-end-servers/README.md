# Back End Servers

A back-end server is the hardware and operating system on the back end that hosts all of the applications necessary to run the web application. It is the real system running all of the processes and carrying out all of the tasks that make up the entire web application. The back end server would fit in the [Data access layer](https://en.wikipedia.org/wiki/Data\_access\_layer).

***

### Software

The back end server contains the other 3 back end components:

* `Web Server`
* `Database`
* `Development Framework`

![backend-server](https://academy.hackthebox.com/storage/modules/75/backend-server.jpg)

Other software components on the back end server may include [hypervisors](https://en.wikipedia.org/wiki/Hypervisor), containers, and WAFs.

There are many popular combinations of "stacks" for back-end servers, which contain a specific set of back end components. Some common examples include:

| Combinations                                                          | Components                                         |
| --------------------------------------------------------------------- | -------------------------------------------------- |
| [LAMP](https://en.wikipedia.org/wiki/LAMP\_\(software\_bundle\))      | `Linux`, `Apache`, `MySQL`, and `PHP`.             |
| [WAMP](https://en.wikipedia.org/wiki/LAMP\_\(software\_bundle\)#WAMP) | `Windows`, `Apache`, `MySQL`, and `PHP`.           |
| [WINS](https://en.wikipedia.org/wiki/Solution\_stack)                 | `Windows`, `IIS`, `.NET`, and `SQL Server`         |
| [MAMP](https://en.wikipedia.org/wiki/MAMP)                            | `macOS`, `Apache`, `MySQL`, and `PHP`.             |
| [XAMPP](https://en.wikipedia.org/wiki/XAMPP)                          | Cross-Platform, `Apache`, `MySQL`, and `PHP/PERL`. |

We can find a comprehensive list of Web Solution Stacks in this [article](https://en.wikipedia.org/wiki/Solution\_stack).

***

### Hardware

The back end server contains all of the necessary hardware. The power and performance capabilities of this hardware determine how stable and responsive the web application will be. As previously discussed in the `Architecture` section, many architectures, especially for huge web applications, are designed to distribute their load over many back end servers that collectively work together to perform the same tasks and deliver the web application to the end-user. Web applications do not have to run directly on a single back end server but may utilize data centers and cloud hosting services that provide virtual hosts for the web application.

**Questions**

What operating system is 'WAMP' used with?

```bash
Windows
```
