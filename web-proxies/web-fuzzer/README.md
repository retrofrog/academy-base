# Web Fuzzer

## ZAP Fuzzer

***

ZAP's Fuzzer is called (`ZAP Fuzzer`). It can be very powerful for fuzzing various web end-points, though it is missing some of the features provided by Burp Intruder. ZAP Fuzzer, however, does not throttle the fuzzing speed, which makes it much more useful than Burp's free Intruder.

In this section, we will try to replicate what we did in the previous section using ZAP Fuzzer to have an "apples to apples" comparison and decide which one we like best.

***

### Fuzz

To start our fuzzing, we will visit the URL from the exercise at the end of this section to capture a sample request. As we will be fuzzing for directories, let's visit `<http://SERVER_IP:PORT/test/>` to place our fuzzing location on `test` later on. Once we locate our request in the proxy history, we will right-click on it and select (`Attack>Fuzz`), which will open the `Fuzzer` window:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap\_fuzzer.jpg)

The main options we need to configure for our Fuzzer attack are:

* Fuzz Location
* Payloads
* Processors
* Options

Let's try to configure them for our web directory fuzzing attack.

***

### Locations

The `Fuzz Location` is very similar to `Intruder Payload Position`, where our payloads will be placed. To place our location on a certain word, we can select it and click on the `Add` button on the right pane. So, let's select `test` and click on `Add`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap\_fuzzer\_add.jpg)

As we can see, this placed a `green` marker on our selected location and opened the `Payloads` window for us to configure our attack payloads.

***

### Payloads

The attack payloads in ZAP's Fuzzer are similar in concept to Intruder's Payloads, though they are not as advanced as Intruder's. We can click on the `Add` button to add our payloads and select from 8 different payload types. The following are some of them:

* `File`: This allows us to select a payload wordlist from a file.
* `File Fuzzers`: This allows us to select wordlists from built-in databases of wordlists.
* `Numberzz`: Generates sequences of numbers with custom increments.

One of the advantages of ZAP Fuzzer is having built-in wordlists we can choose from so that we do not have to provide our own wordlist. More databases can be installed from the ZAP Marketplace, as we will see in a later section. So, we can select `File Fuzzers` as the `Type`, and then we will select the first wordlist from `dirbuster`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap\_fuzzer\_add\_payload.jpg)

Once we click the `Add` button, our payload wordlist will get added, and we can examine it with the `Modify` button.

***

### Processors

We may also want to perform some processing on each word in our payload wordlist. The following are some of the payload processors we can use:

* Base64 Decode/Encode
* MD5 Hash
* Postfix String
* Prefix String
* SHA-1/256/512 Hash
* URL Decode/Encode
* Script

As we can see, we have a variety of encoders and hashing algorithms to select from. We can also add a custom string before the payload with `Prefix String` or a custom string with `Postfix String`. Finally, the `Script` type allows us to select a custom script that we built and run on every payload before using it in the attack.

We will select the `URL Encode` processor for our exercise to ensure that our payload gets properly encoded and avoid server errors if our payload contains any special characters. We can click on the `Generate Preview` button to preview how our final payload will look in the request:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap\_fuzzer\_add\_processor.jpg)

Once that's done, we can click on `Add` to add the processor and click on `Ok` in the processors and payloads windows to close them.

***

### Options

Finally, we can set a few options for our fuzzers, similar to what we did with Burp Intruder. For example, we can set the `Concurrent threads per scan` to `20`, so our scan runs very quickly:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap\_fuzzer\_options.jpg)

The number of threads we set may be limited by how much computer processing power we want to use or how many connections the server allows us to establish.

We may also choose to run through the payloads `Depth first`, which would attempt all words from the wordlist on a single payload position before moving to the next (e.g., try all passwords for a single user before brute-forcing the following user). We could also use `Breadth first`, which would run every word from the wordlist on all payload positions before moving to the next word (e.g., attempt every password for all users before moving to the following password).

***

### Start

With all of our options configured, we can finally click on the `Start Fuzzer` button to start our attack. Once our attack is started, we can sort the results by the `Response` code, as we are only interested in responses with code `200`:

![payload processing](https://academy.hackthebox.com/storage/modules/110/zap\_fuzzer\_attack.jpg)

As we can see, we got one hit with code `200` with the `skills` payload, meaning that the `/skills/` directory exists on the server and is accessible. We can click on the request in the results window to view its details: ![payload processing](https://academy.hackthebox.com/storage/modules/110/zap\_fuzzer\_dir.jpg)

We can see from the response that this page is indeed accessible by us. There are other fields that may indicate a successful hit depending on the attack scenario, like `Size Resp. Body` which may indicate that we got a different page if its size was different than other responses, or `RTT` for attacks like `time-based SQL injections`, which are detected by a time delay in the server response.
