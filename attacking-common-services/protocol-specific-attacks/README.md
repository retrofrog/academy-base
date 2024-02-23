# Protocol Specific Attacks

## The Concept of Attacks

***

To effectively understand attacks on the different services, we should look at how these services can be attacked. A concept is an outlined plan that is applied to future projects. As an example, we can think of the concept of building a house. Many houses have a basement, four walls, and a roof. Most homes are built this way, and it is a concept that is applied all over the world. The finer details, such as the material used or the type of design, are flexible and can be adapted to individual wishes and circumstances. This example shows that a concept needs a general categorization (floor, walls, roof).

In our case, we need to create a concept for the attacks on all possible services and divide it into categories that summarize all services but leave the individual attack methods.

To explain a little more clearly what we are talking about here, we can try to group the services SSH, FTP, SMB, and HTTP ourselves and figure out what these services have in common. Then we need to create a structure that will allow us to identify the attack points of these different services using a single pattern.

Analyzing commonalities and creating pattern templates that fit all conceivable cases is not a finished product but rather a process that makes these pattern templates grow larger and larger. Therefore, we have created a pattern template for this topic for you to better and more efficiently teach and explain the concept behind the attacks.

**The Concept of Attacks**

![](https://academy.hackthebox.com/storage/modules/116/attack\_concept2.png)

The concept is based on four categories that occur for each vulnerability. First, we have a `Source` that performs the specific request to a `Process` where the vulnerability gets triggered. Each process has a specific set of `Privileges` with which it is executed. Each process has a task with a specific goal or `Destination` to either compute new data or forward it. However, the individual and unique specifications under these categories may differ from service to service.

Every task and piece of information follows a specific pattern, a cycle, which we have deliberately made linear. This is because the `Destination` does not always serve as a `Source` and is therefore not treated as a source of a new task.

For any task to come into existence at all, it needs an idea, information (`Source`), a planned process for it (`Processes`), and a specific goal (`Destination`) to be achieved. Therefore, the category of `Privileges` is necessary to control information processing appropriately.

***

### Source

We can generalize `Source` as a source of information used for the specific task of a process. There are many different ways to pass information to a process. The graphic shows some of the most common examples of how information is passed to the processes.

| **Information Source** | **Description**                                                                                                                                                                                    |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Code`                 | This means that the already executed program code results are used as a source of information. These can come from different functions of a program.                                               |
| `Libraries`            | A library is a collection of program resources, including configuration data, documentation, help data, message templates, prebuilt code and subroutines, classes, values, or type specifications. |
| `Config`               | Configurations are usually static or prescribed values that determine how the process processes information.                                                                                       |
| `APIs`                 | The application programming interface (API) is mainly used as the interface of programs for retrieving or providing information.                                                                   |
| `User Input`           | If a program has a function that allows the user to enter specific values used to process the information accordingly, this is the manual entry of information by a person.                        |

The source is, therefore, the source that is exploited for vulnerabilities. It does not matter which protocol is used because HTTP header injections can be manipulated manually, as can buffer overflows. The source for this can therefore be categorized as `Code`. So let us take a closer look at the pattern template based on one of the latest critical vulnerabilities that most of us have heard of.

**Log4j**

A great example is the critical Log4j vulnerability ([CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=cve-2021-44228)) which was published at the end of 2021. Log4j is a framework or `Library` used to log application messages in Java and other programming languages. This library contains classes and functions that other programming languages can integrate. For this purpose, information is documented, similar to a logbook. Furthermore, the scope of the documentation can be configured extensively. As a result, it has become a standard within many open source and commercial software products. In this example, an attacker can manipulate the HTTP User-Agent header and insert a JNDI lookup as a command intended for the Log4j `library`. Accordingly, not the actual User-Agent header, such as Mozilla 5.0, is processed, but the JNDI lookup.

***

### Processes

The `Process` is about processing the information forwarded from the source. These are processed according to the intended task determined by the program code. For each task, the developer specifies how the information is processed. This can occur using classes with different functions, calculations, and loops. The variety of possibilities for this is as diverse as the number of developers in the world. Accordingly, most of the vulnerabilities lie in the program code executed by the process.

| **Process Components** | **Description**                                                                                                                                                            |
| ---------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `PID`                  | The Process-ID (PID) identifies the process being started or is already running. Running processes have already assigned privileges, and new ones are started accordingly. |
| `Input`                | This refers to the input of information that could be assigned by a user or as a result of a programmed function.                                                          |
| `Data processing`      | The hard-coded functions of a program dictate how the information received is processed.                                                                                   |
| `Variables`            | The variables are used as placeholders for information that different functions can further process during the task.                                                       |
| `Logging`              | During logging, certain events are documented and, in most cases, stored in a register or a file. This means that certain information remains in the system.               |

**Log4j**

The process of Log4j is to log the User-Agent as a string using a function and store it in the designated location. The vulnerability in this process is the misinterpretation of the string, which leads to the execution of a request instead of logging the events. However, before we go further into this function, we need to talk about privileges.

***

### Privileges

`Privileges` are present in any system that controls processes. These serve as a type of permission that determines what tasks and actions can be performed on the system. In simple terms, it can be compared to a bus ticket. If we use a ticket intended for a particular region, we will be able to use the bus, and otherwise, we will not. These privileges (or figuratively speaking, our tickets) can also be used for different means of transport, such as planes, trains, boats, and others. In computer systems, these privileges serve as control and segmentation of actions for which different permissions, controlled by the system, are needed. Therefore, the rights are checked based on this categorization when a process needs to fulfill its task. If the process satisfies these privileges and conditions, the system approves the action requested. We can divide these privileges into the following areas:

| **Privileges** | **Description**                                                                                                                                                                                           |
| -------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `System`       | These privileges are the highest privileges that can be obtained, which allow any system modification. In Windows, this type of privilege is called `SYSTEM`, and in Linux, it is called `root`.          |
| `User`         | User privileges are permissions that have been assigned to a specific user. For security reasons, separate users are often set up for particular services during the installation of Linux distributions. |
| `Groups`       | Groups are a categorization of at least one user who has certain permissions to perform specific actions.                                                                                                 |
| `Policies`     | Policies determine the execution of application-specific commands, which can also apply to individual or grouped users and their actions.                                                                 |
| `Rules`        | Rules are the permissions to perform actions handled from within the applications themselves.                                                                                                             |

**Log4j**

What made the Log4j vulnerability so dangerous was the `Privileges` that the implementation brought. Logs are often considered sensitive because they can contain data about the service, the system itself, or even customers. Therefore, logs are usually stored in locations that no regular user should be able to access. Accordingly, most applications with the Log4j implementation were run with the privileges of an administrator. The process itself exploited the library by manipulating the User-Agent so that the process misinterpreted the source and led to the execution of user-supplied code.

***

### Destination

Every task has at least one purpose and goal that must be fulfilled. Logically, if any data set changes were missing or not stored or forwarded anywhere, the task would be generally unnecessary. The result of such a task is either stored somewhere or forwarded to another processing point. Therefore we speak here of the `Destination` where the changes will be made. Such processing points can point either to a local or remote process. Therefore, at the local level, local files or records may be modified by the process or be forwarded to other local services for further use. However, this does not exclude the possibility that the same process could reuse the resulting data too. If the process is completed with the data storage or its forwarding, the cycle leading to the task's completion is closed.

| **Destination** | **Description**                                                                                                                                                                                                                                               |
| --------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Local`         | The local area is the system's environment in which the process occurred. Therefore, the results and outcomes of a task are either processed further by a process that includes changes to data sets or storage of the data.                                  |
| `Network`       | The network area is mainly a matter of forwarding the results of a process to a remote interface. This can be an IP address and its services or even entire networks. The results of such processes can also influence the route under certain circumstances. |

**Log4j**

The misinterpretation of the User-Agent leads to a JNDI lookup which is executed as a command from the system with administrator privileges and queries a remote server controlled by the attacker, which in our case is the `Destination` in our concept of attacks. This query requests a Java class created by the attacker and is manipulated for its own purposes. The queried Java code inside the manipulated Java class gets executed in the same process, leading to a remote code execution (`RCE`) vulnerability.

GovCERT.ch has created an excellent graphical representation of the Log4j vulnerability worth examining in detail.

![](https://academy.hackthebox.com/storage/modules/116/log4jattack.png) Source: https://www.govcert.ch/blog/zero-day-exploit-targeting-popular-java-library-log4j/

This graphic breaks down the Log4j JNDI attack based on the `Concept of Attacks`.

**Initiation of the Attack**

| **Step** | **Log4j**                                                                                                                                                               | **Concept of Attacks - Category** |
| -------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `1.`     | The attacker manipulates the user agent with a JNDI lookup command.                                                                                                     | `Source`                          |
| `2.`     | The process misinterprets the assigned user agent, leading to the execution of the command.                                                                             | `Process`                         |
| `3.`     | The JNDI lookup command is executed with administrator privileges due to logging permissions.                                                                           | `Privileges`                      |
| `4.`     | This JNDI lookup command points to the server created and prepared by the attacker, which contains a malicious Java class containing commands designed by the attacker. | `Destination`                     |

This is when the cycle starts all over again, but this time to gain remote access to the target system.

**Trigger Remote Code Execution**

| **Step** | **Log4j**                                                                                                                                    | **Concept of Attacks - Category** |
| -------- | -------------------------------------------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `5.`     | After the malicious Java class is retrieved from the attacker's server, it is used as a source for further actions in the following process. | `Source`                          |
| `6.`     | Next, the malicious code of the Java class is read in, which in many cases has led to remote access to the system.                           | `Process`                         |
| `7.`     | The malicious code is executed with administrator privileges due to logging permissions.                                                     | `Privileges`                      |
| `8.`     | The code leads back over the network to the attacker with the functions that allow the attacker to control the system remotely.              | `Destination`                     |

Finally, we see a pattern that we can repeatedly use for our attacks. This pattern template can be used to analyze and understand exploits and debug our own exploits during development and testing. In addition, this pattern template can also be applied to source code analysis, which allows us to check certain functionality and commands in our code step-by-step. Finally, we can also think categorically about each task's dangers individually.
