With studies estimating that over 40% of all internet traffic originates from bots, there has been a rise in demand for software that can distinguish human activity from bot activity. A prime example of this is _[Cloudflare's Bot Management Solution](https://www.cloudflare.com/products/bot-management/)_.

If you clicked on this article, you probably want to learn how to bypass Cloudflare. You've come to the right place! In this guide, we'll cover:

-   What is Cloudflare Bot Management
-   How Cloudflare Detects Bots
-   How to reverse engineer and bypass Cloudflare

Ready? Let's get started!

## What is Cloudflare Bot Management

Cloudflare is a web performance and security company. On the security side, they offer customers a [Web Application Firewall (WAF)](https://www.cloudflare.com/waf/). A WAF can defend applications against several security threats, such as cross-site scripting (XSS), credential stuffing, and DDoS attacks.

One of the core systems included in their WAF is Cloudflare's Bot Manager. As a bot protection solution, its main goal is to **mitigate attacks from malicious bots without impacting real users**.

Cloudflare acknowledges the importance of certain bots. For example, no site wants to deliberately block Google or other search engines from crawling its webpage. To account for this, Cloudflare maintains an [allowlist for known good bots](https://www.cloudflare.com/learning/bots/how-to-manage-good-bots/).

Unfortunately for web-scraping enthusiasts like you and me, they also assume all non-whitelisted bot traffic is malicious. So, _regardless of your intent_, there's a good chance **your bot gets denied access to a Cloudflare-protected web page**.

If you've tried to scrape a Cloudflare-protected site before, you may have run into a few of the following [Bot-manager related errors](https://support.cloudflare.com/hc/en-us/articles/360029779472-Troubleshooting-Cloudflare-1XXX-errors):

-   **Error 1020**: Access Denied
-   **Error 1010**: The owner of this website has banned your access based on your browser's signature
-   **Error 1015**: You are being rate limited
-   **Error 1012**: Access Denied

Which are usually accompanied by a `403 Forbidden` HTTP response status code.

### Can Cloudflare be bypassed?

Thankfully, **the answer is _yes_!** But, developing a Cloudflare bypass is no simple feat to do on your own. First, you'll need to develop a solid understanding of how it works.

## How does Cloudflare detect bots?

The bot detection methods used by Cloudflare can generally be classified into two categories: **passive** and **active**. Passive bot detection techniques consist of fingerprinting checks performed on the backend, while active detection techniques rely on checks performed on the client side. Let's dive into a few examples from each category together!

### Cloudflare passive bot detection techniques

Here's a non-exhaustive list of some passive bot detection techniques Cloudflare employs:

#### Detecting botnets

Cloudflare maintains a catalog of devices, IP addresses, and behavioral patterns known to be associated with **malicious bot networks**. Any device suspected to belong to one of these networks is either automatically blocked or faced with additional client-side challenges to solve.

#### IP address reputation

A user's IP address reputation (also known as **risk score** or **fraud score**) is based on factors such as geolocation, ISP, and reputation history. For example, IPs belonging to a data center or known VPN provider will have a worse reputation than a residential IP address. A site may also choose to limit access to a site from regions outside of the area they serve since traffic from an actual customer should never come from there.

#### HTTP request headers

Cloudflare uses HTTP request headers to determine if you're a robot. If you have a non-browser user agent, such as `python-requests/2.22.0`, your scraper can easily be picked out as a bot. Cloudflare can also block your bot if it sends a request that is missing headers that would otherwise be there in a browser. Or if you have mismatching headers based on your user-agent. For example, including a `sec-ch-ua-full-version-list:` header for a Firefox user-agent.

#### TLS fingerprinting

This technique enables Cloudflare's antibot to **identify the client** being used to send requests to a server.

Though there are multiple methods of fingerprinting TLS (such as [JA3](https://engineering.salesforce.com/tls-fingerprinting-with-ja3-and-ja3s-247362855967/), [JARM](https://engineering.salesforce.com/easily-identify-malicious-servers-on-the-internet-with-jarm-e095edac525a/), and [CYU](https://engineering.salesforce.com/gquic-protocol-analysis-and-fingerprinting-in-zeek-a4178855d75f/)), each implementation produces a fingerprint that _is static per request client_. TLS fingerprinting is helpful because the **TLS implementation of a browser tends to differ from that of other release versions, other browsers, and request-based libraries**. For example, a Chrome browser on Windows (version 104) would have a different fingerprint than all of the following:

-   A Chrome browser on Windows (version 87)
-   A Firefox browser
-   A Chrome browser on an android device
-   The [python HTTP requests library](https://pypi.org/project/requests/)

The construction of a TLS fingerprint happens during the [TLS Handshake](https://www.cloudflare.com/learning/ssl/what-happens-in-a-tls-handshake/). Cloudflare analyzes the fields provided in the **'client hello'** message, such as _cipher suites_, _extensions_, and _elliptic curves_, to compute a fingerprint hash for a given client.

Next, that hash is looked up in a database of **pre-collected fingerprints** to determine the client the request came from. Suppose the client's hash matches an allowed fingerprint hash (i.e., a browser's fingerprint). In that case, Cloudflare will then compare the user-agent header from the client's request to the user-agent associated with the stored fingerprint hash.

**If they match, the security system assumes that the request originated from a standard browser**. On the contrary, **a mismatch between a client's TLS fingerprint and its advertised user-agent indicates obvious use of custom botting software**, resulting in the request being blocked.

#### HTTP/2 fingerprinting

The HTTP/2 specification is the second major HTTP protocol version, published on May 14, 2015, as [RFC 7540](https://datatracker.ietf.org/doc/html/rfc7540). As of the time of writing (September 2022), the protocol is supported by all major browsers.

The main goal of HTTP/2 was to **improve the performance of websites and web applications** by introducing header field compression and allowing concurrent requests and responses on the same TCP connection. To accomplish this, HTTP/1.1's foundation was expanded with new parameters and values. These new internals are what the HTTP/2 fingerprint is based on.

The **[binary framing layer](https://httpwg.org/specs/rfc7540.html#FramingLayer)** is a new addition to HTTP/2 and is the **central focus of an HTTP/2 fingerprint**.

If you're interested in a more in-depth analysis of HTTP/2 fingerprinting, you should read Akamai's proposed method for fingerprinting HTTP2 clients here: [Passive Fingerprinting of HTTP/2 Clients](https://www.blackhat.com/docs/eu-17/materials/eu-17-Shuster-Passive-Fingerprinting-Of-HTTP2-Clients-wp.pdf). But for now, here's a summary:

Three main components form an HTTP/2 fingerprint:

-   **Frames**: `SETTINGS_HEADER_TABLE_SIZE`, `SETTINGS_ENABLE_PUSH`, `SETTINGS_MAX_CONCURRENT_STREAMS`, `SETTINGS_INITIAL_WINDOW_SIZE`, `SETTINGS_MAX_FRAME_SIZE`, `SETTINGS_MAX_HEADER_LIST_SIZE`, `WINDOW_UPDATE`
-   **Stream Priority Information**: `StreamID:Exclusivity_Bit:Dependant_StreamID:Weight`
-   **Pseudo Header Fields Order**: The order of the `:method`,`:authority`, `:scheme`, and `:path` headers.

If you're curious, you can test a live HTTP/2 fingerprinting demo by clicking [here](https://privacycheck.sec.lrz.de/passive/fp_h2/fp_http2.html).

Like TLS fingerprinting, **each request client will have a static HTTP/2 fingerprint**. To determine a request's legitimacy, Cloudflare always verifies that the fingerprint and user-agent pair from the request matches a whitelisted one stored in their database.

**HTTP/2 fingerprinting and TLS fingerprinting go hand in hand.** Out of all the passive bot detection techniques Cloudflare uses, these two are the most technically challenging to control in a request-based bot. However, they're also the most important. So, you want to ensure you do them right or risk getting blocked!

Alright! By now, you should have a good understanding of how Cloudflare detects bots _passively_. But, remember: that's only half of the story. Now, let's take a look at how they do it _actively_!

### Cloudflare active bot detection techniques

When you visit a Cloudflare-protected website, many checks are constantly running on the **client-side** (i.e., in your local browser) to determine if you're a robot. Here's a list of some methods they use (once again, non-exhaustive):

#### CAPTCHAs

In the past, CAPTCHAs were the go-to method for detecting bots. However, it's well-known that they harm the end user's experience. Whether or not Cloudflare serves the user a captcha is dependent on several factors, such as:

-   **The site configuration.** A website administrator may choose to enable CAPTCHAs **all the time, sometimes, or never at all.**
-   **Risk Level.** Cloudflare may choose to serve a CAPTCHA only if the traffic is suspicious. For example, a CAPTCHA may be shown if a user browses a site using the Tor client, but not if the user runs a standard web browser like Google Chrome.

Previously, Cloudflare used reCAPTCHA as their primary captcha provider. But, since 2020, they've migrated to use hCaptcha exclusively. Below is an example of hCaptcha appearing on a Cloudflare-protected site:

[![Cloudflare hCaptcha Integration](https://cdn.zenrows.com/images/blog/bypass-cloudflare-hcaptcha-400.jpg "Cloudflare hCaptcha Integration")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-hcaptcha.jpg)

Click to open the image in fullscreen

#### Canvas fingerprinting

Canvas fingerprinting allows a system to identify the _device class_ of a web client. A device class refers to the **combination of browser, operating system, and graphics hardware** of the system used to access the webpage.

Canvas is an **HTML5 API used to draw graphics and animations on a web page** using JavaScript. To construct a canvas fingerprint, a webpage queries your browser's canvas API to render an image. That image is then hashed to produce a fingerprint.

This technique relies on taking a system's graphic rendering system as a [physically unclonable function](https://en.wikipedia.org/wiki/Physical_unclonable_function). That might sound complicated, so let me explain it.

A canvas fingerprint depends on multiple layers of the computing system, such as:

-   **Hardware**. GPU
-   **Low-level Software**. GPU driver, Operating system (fonts, anti-aliasing/sub-pixel rendering algorithms)
-   **High-Level Software** Web Browser (image processing engine)

Because a variation in any of these categories will produce a unique fingerprint, this technique accurately differentiates between device classes.

I want to clarify this: **a canvas fingerprint doesn't contain enough information to sufficiently track and identify unique individuals or bots**. Instead, its **main purpose is to distinguish between device classes accurately**.

In the context of bot detection, this is useful because bots tend to lie about their underlying technology (via their user-agent header). Cloudflare has a **large dataset of legitimate canvas fingerprints + user agent pairs**. Using **machine learning**, they can detect device property spoofing (ex. user-agent, operating system, or GPU) by looking for a mismatch between your canvas fingerprint and the expected one.

Cloudflare uses a specific canvas fingerprinting method, Google's _[Picasso Fingerprinting](https://ai.google/research/pubs/pub45581)_.

If you'd like to see canvas fingerprinting in action, check out [Browserleak's live demo](https://browserleaks.com/canvas).

#### Event tracking

Cloudflare adds [event listeners](https://developer.mozilla.org/en-US/docs/Web/API/EventTarget/addEventListener) to webpages. These listen for user actions, such as mouse movements, mouse clicks, or key presses. Most of the time, a real user will need to use their mouse or keyboard to browse. If Cloudflare sees a consistent lack of mouse or keyboard usage, they can assume the user is a bot.

#### Environment API querying

This is a **_very_** broad category. A browser has [hundreds of Web APIs](https://developer.mozilla.org/en-US/docs/Web/API) that can be used for bot detection. I'll do my best to split them up into **4** categories:

1.  **Browser-specific APIs**. These specifications exist in one browser but may not exist in another. For example, `window.chrome` is a property that only exists in a Chrome browser. If the data you send Cloudflare indicates that you're using a Chrome browser but send it with a Firefox user agent, they'll know something is up.
2.  **Timestamp APIs**. Cloudflare makes use of timestamp APIs, such as `Date.now()` or `window.performance.timing.navigationStart` to keep track of a user's speed metrics. A user will be blocked if timestamps don't appear like ordinary human browsing activity. Some examples include: browsing inhumanly quickly or mismatching timestamps (such as a `navigationStart` timestamp from before the page was loaded).
3.  **Automated Browser Detection**. Cloudflare queries the browser for properties that only exist in automated web browser environments. For example, the existence of the `window.document.__selenium_unwrapped` or `window.callPhantom` property indicates the usage of [Selenium](https://www.selenium.dev/) and [PhantomJS](https://phantomjs.org/), respectively. For obvious reasons, you're getting blocked if this is detected.
4.  **Sandboxing Detection**. For our purposes, **sandboxing refers to an attempt at emulating a browser in a non-browser environment.** Cloudflare has checks to stop people from trying to solve its challenges with emulated browser environments, such as in NodeJS using JSDOM. For example, the script may look for the `process` object, which only exists in NodeJS. They also can detect if functions have been modified by using `Function.prototype.toString.call(functionName)` on the function in question.

### The core of Cloudflare bot protection

Like many other antibots, Cloudflare collects the data from all of the above methods as _sensor data_ and validates it for inconsistencies on the server side.

Whew, that was a lot of info! You should now have an understanding of the bot detection techniques used by Cloudflare.

So far, we've only discussed the high-level concepts without too many specifics regarding Cloudflare's actual script. But don't worry. In this next section, we're going to see exactly how Cloudflare's antibot puts these techniques into practice; by analyzing its core: the Cloudflare waiting room.

## Cloudflare waiting Room

> Checking if the site connection is secure

> Checking your browser before accessing XXXXXXXX.com

Does that ring a bell? If you're reading this article, you've probably previously run into Cloudflare's _waiting room_:

[![Cloudflare Waiting Room](https://cdn.zenrows.com/images/blog/bypass-cloudflare-challenge-page-640.png "Cloudflare Waiting Room")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-challenge-page.png)

Click to open the image in fullscreen

Also known as the Cloudflare _JavaScript challenge_ or the Cloudflare _I Am Under Attack_ page, this is Cloudflare's principal protection. **If you want to bypass Cloudflare, you need to bypass this page.**

When you visit a Cloudflare-protected site in your browser, you'll first need to wait a few seconds in the Cloudflare waiting room. **During that time, your browser solves challenges to prove you're not a robot.** If you're labeled as a bot, you'll be given an "Access Denied" error. Otherwise, you'll get automatically redirected to the actual web page.

Once the challenge has been solved once, you're free to browse the site for a while without needing to wait again.

But what exactly goes on during those few seconds of wait time? **If you hope to bypass Cloudflare, you need to fully understand its internals to trick its verification process**.

To answer that question, we're going to do a deep dive into Cloudflare's JavaScript challenge and show you how to reverse engineer it. Buckle your seatbelts because this is about to get technical!

## Reverse engineering the Cloudflare JavaScript challenge

**If you want to make your own bypass for any antibot system, you first need to reverse engineer it**. Creating a Cloudflare bypass is no different.

For this example, we're going to reverse engineer the Cloudflare waiting room page as it appears on [AW LAB](https://en.aw-lab.com/). Feel free to click the link and follow along!

### Step 1: checking out the network log

First things first, open up the developer tools in your browser and navigate to the 'Network' tab. Then, we'll leave them open and browse the AW LAB site.

After we are redirected from the challenge page to the actual site, we'll notice the following crucial requests (in chronological order):

-   An initial `GET` to `https://en.aw-lab.com/`, with the response body as the waiting room's HTML. The HTML contains `<script>` tags containing an important anonymous function. **This function does some initialization and loads the "initial challenge" script.**
    
    ```
    // The script from the waiting room HTML. 
    (function () { 
    window._cf_chl_opt = { 
    cvId: '2', 
    cType: 'non-interactive', 
    cNounce: '12107', 
    cRay: '744da33dfa643ff2', 
    cHash: 'c9f67a0e7ada3f3', 
    /* ... */ 
    }; 
    var trkjs = document.createElement('img'); 
    /* ... */ 
    var cpo = document.createElement('script'); 
    cpo.src = '/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1?ray=744da33dfa643ff2'; 
    window._cf_chl_opt.cOgUHash = /* ... */ 
    window._cf_chl_opt.cOgUQuery = /* ... */ 
    if (window.history && window.history.replaceState) { 
    /* ... */ 
    } 
    document.getElementsByTagName('head')[0].appendChild(cpo); 
    })();
    ```
    
    This script (along with the many more to come) rotates per request, so it may look slightly different for you if you're following along in your browser.
-   A `GET` to the "initial challenge" script: `https://en.aw-lab.com/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1?ray=<rayID>`, where `<rayId>` is the value of `window._cf_chl_opt.cRay` from above. It returns an obfuscated JavaScript script, which you can view [here](https://en.aw-lab.com/cdn-cgi/challenge-platform/h/g/orchestrate/jsch/v1). Note: this script rotates changes on each request.
    
    [![The GET request for the 'initial challenge' script](https://cdn.zenrows.com/images/blog/bypass-cloudflare-initial-challenge-get.png "The GET request for the 'initial challenge' script")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-initial-challenge-get.png)
    
    Click to open the image in fullscreen
    
-   A `POST` request to `https://en.aw-lab.com/cdn-cgi/challenge-platform/h/g/flow/ov1/<parsedStringFromJS>/<rayID>/<cHash>`, where `<parsedStringFromJS>` is a string defined in the initial challenge script and `<cHash>` is the value of `window._cf_chl_opt.cHash`. The request body is a URL-encoded payload of the format: `v_<rayID>=<initialChallengeSolution>`. The response body to this request seems to be a long base64-encoded string.
    
    [![The initial challenge request. Payload (Left), Response (Right)](https://cdn.zenrows.com/images/blog/bypass-cloudflare-initial-challenge-solve.png "The initial challenge request. Payload (Left), Response (Right)")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-initial-challenge-solve.png)
    
    Click to open the image in fullscreen
    
-   A second `POST` request to `https://en.aw-lab.com/cdn-cgi/challenge-platform/h/g/flow/ov1/<parsedStringFromJS>/<rayID>/<cHash>`. The payload follows the same format as the previous request and, once again, returns a long base64-encoded string. This request is responsible for sending the solution of the second Cloudflare challenge.
    
    [![The second challenge request. Payload (Left), Response (Right)](https://cdn.zenrows.com/images/blog/bypass-cloudflare-second-challenge-solve.png "The second challenge request. Payload (Left), Response (Right)")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-second-challenge-solve.png)
    
    Click to open the image in fullscreen
    
-   A final `POST` request to `https://en.aw-lab.com/`, with some crypto form data in this format:
    
    ```
    md: <string> 
    r: <string> 
    sh: <string> 
    aw: <string> 
    ```
    
    This response to this request gives us the actual HTML of the target webpage **and a `cf_clearance` cookie that allows us to freely access the site without needing to solve another challenge.**
    
    [![The final POST request. Payload (Left), Response Cookies (Right)](https://cdn.zenrows.com/images/blog/bypass-cloudflare-final-post.png "The final POST request. Payload (Left), Response Cookies (Right)")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-final-post.png)
    
    Click to open the image in fullscreen
    

The request flow doesn't give us too much information, **especially since all the data looks to be either encrypted or a random text stream**. So, that rules out trying to black-box reverse engineer our way to a Cloudflare bypass.

**This might leave you with even more questions than you started with.** Where do these requests come from? What does the data in the payloads represent? What's the purpose of the base64 response bodies?

Well, **there's no better place to search for answers than the "initial challenge" script.** We've avoided looking at Cloudflare's code in-depth up until now, but now we're left with no other choice. Be warned, this is no walk in the park! If you're ready for the challenge, stick with us. We'll start with some _dynamic analysis_.

### Step 2: debugging the Cloudflare Javascript challenge script

Cloudflare's scripts are _heavily obfuscated_. It would be a nightmare to dive right into trying to read the script as-is with little knowledge of its functionality.

Fortunately for us, at the time of writing this, Cloudflare doesn't use any kind of anti-debugging protection. Open up your browser's developer tools, and set up an [XHR/fetch breakpoint](https://developer.chrome.com/docs/devtools/javascript/breakpoints/#xhr) for all requests:

[![Setting an xhr breakpoint](https://cdn.zenrows.com/images/blog/bypass-cloudflare-xhr-breakpoint-640.png "Setting an xhr breakpoint")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-xhr-breakpoint.png)

Click to open the image in fullscreen

Be sure to clear your cookies so that Cloudflare will place you in the waiting room again. Keeping your developer tools open, navigate to [AW LAB](https://en.aw-lab.com/).

You'll notice that within a few milliseconds after the "initial challenge" script loads, your XHR breakpoint gets triggered (before the first POST request is sent).

[![1st Triggered XHR Breakpoint](https://cdn.zenrows.com/images/blog/bypass-cloudflare-breakpoint-640.png "1st Triggered XHR Breakpoint")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-breakpoint.png)

Click to open the image in fullscreen

Now, you can see and access all the variables and functions in the current scope. However, there isn't much you can deduce from the variable values shown on-screen, and the code is unreadable.

Looking closely at the script, **you'll notice that one function is called over a thousand times**. In this example, that's the `c` function (though it might have a different name in your script). When called, there is always a single stringified hex number as the argument. Let's try running it in the DevTools console:

[![Running the 'c' function in the console](https://cdn.zenrows.com/images/blog/bypass-cloudflare-string-concealing.png "Running the 'c' function in the console")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-string-concealing.png)

Click to open the image in fullscreen

Wow! So it appears that Cloudflare uses a string-concealing obfuscation mechanism. By running the function and replacing its calls with its return values, we can simplify the bottom two lines in the above screenshot to this:

```
// The simplified code 
(aG = aw["Cowze"](JSON["stringify"](o["_cf_chl_ctx"]))["replace"]("+", "%2b")), 
aE["send"](aB.FptpP(aB.RfgQh("v_" + o["_cf_chl_opt"]["cRay"], "="), aG));
```

Using the same technique of running code in the console, we can deduce that the variables `o` and `aE` represent `window` and an `XMLHttpRequest` instance, respectively. We can also convert bracket notation to dot notation to yield:

```
// The above code, even more simplified! 
(aG = aw.Cowze(JSON.stringify(window._cf_chl_ctx)).replace("+", "%2b")), 
// aE = new XMLHttpRequest(), an XMLHttpRequest instance initialized earlier in the script 
aE.send(aB.FptpP(aB.RfgQh("v_" + window._cf_chl_opt.cRay, "="), aG));
```

It's not perfect, but the code is getting a lot easier for us to read. Simplifying all the string-concealing function calls would improve the script's readability. However, doing it manually would take an eternity. We'll tackle this challenge in the next section, but let's move on for now.

If you press the "continue until next breakpoint" button in your debugger, your browser will send the first post request. Immediately after receiving a response, it will pause on the next breakpoint:

[![2nd Triggered XHR Breakpoint](https://cdn.zenrows.com/images/blog/bypass-cloudflare-breakpoint2-640.png "2nd Triggered XHR Breakpoint")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-breakpoint2.png)

Click to open the image in fullscreen

What a plot twist! The debugger is paused in a completely different script. This new script is what we'll call Cloudflare's "main" or "second" Javascript challenge. But, **if you look at the network log, there was no `GET` request to this specific script**! So, where did it come from?

Taking a closer look at the script, we can see that it's an anonymous function. The script name, in our case, is `VM279`. According to [this thread](https://stackoverflow.com/questions/17367560/chrome-development-tool-vm-file-from-javascript) on StackOverflow, this second script is likely being evaluated within the initial challenge script, using `eval` or similar. We can confirm this because the call stack shows the Cloudflare "initial challenge" script as the initiator (_see: green boxes in the screenshot_)!

If we click on the initiator, we can see where this script is being evaluated in the "initial challenge" script:

[![Location of the initiator](https://cdn.zenrows.com/images/blog/bypass-cloudflare-newfunc-640.png "Location of the initiator")](https://cdn.zenrows.com/images/blog/bypass-cloudflare-newfunc.png)

Click to open the image in fullscreen

We'll use the same method of evaluating the `c` function calls to undo the string concealing and replacing `o` with `window`, which gives us this:

```
// The line of code that initiates the second JavaScript challenge 
 
// Note: aE = new XMLHttpRequest(), an XMLHttpRequest instance initialized earlier in the script 
new window.Function(aB.pgNsC(ax, aE.responseText))();
```

It looks like this function is creating a new function based on the data contained in the `responseText` of the XMLHttpRequest from the previous breakpoint. Cloudflare probably uses some cipher to decrypt it into an executable script.

Okay, we've made some progress. Yet as is, the Cloudflare scripts remain unreadable. Even with manual debugging, we won't be able to figure out much more. If you want to create a Cloudflare bypass, we need to be able to understand it _fully_. And to do that, we need to deobfuscate it.

### Step 3: deobfuscating the Cloudflare Javascript challenge script

This isn't going to be trivial. Cloudflare uses _a lot_ of obfuscation techniques in their code, and it wouldn't be practical to cover them all in this article. Here's a (non-exhaustive) list of examples:

-   **[String Concealing](https://docs.jscrambler.com/code-integrity/documentation/transformations/string-concealing)**. Cloudflare removes all references to string literals. In the previous section, we saw that the `c` function acted as a string concealer.
-   **[Control Flow Flattening](https://blog.jscrambler.com/jscrambler-101-control-flow-flattening)**. Cloudflare obscures the control flow of a program by emulating assembly-like `JUMP` instructions by using an infinite loop and a central switch statement dispatcher. Here's an example from the Cloudflare script:
    
    ```
    // An example of control flow flattening from the Cloudflare script. 
    function Y(ay, aD, aC, aB, aA, az) { 
    // The aB array holds a list of all the instructions. 
    aB = "1|6|11|0|15|9|3|10"["split"]("|"); 
     
    // This is the infinite loop 
    for (aC = 0; true; ) { 
    // The below switch statement is the "dispatcher" 
    // The value of the aB[aC] acts as an instruction pointer, determining which switch case to execute. 
    // After each switch statement finishes executing, the instruction pointer is incremented by one to retrieve the next instruction. 
     
    switch (aB[aC++]) { 
    case "0": 
    /* ... */ 
    continue; 
     
    case "1": 
    /* ... */ 
    continue; 
     
    case "3": 
    /* ... */ 
    continue; 
     
    case "6": 
    /* ... */ 
    continue; 
     
    case "9": 
    /* ... */ 
    continue; 
     
    case "10": 
    // Exit the function. This is the final switch case 
    return aD; 
     
    case "11": 
    /* ... */ 
    continue; 
     
    case "15": 
    /* ... */ 
    continue; 
    } 
     
    break; 
    } 
    }
    ```
    
-   **Proxy Functions**. Cloudflare replaces all binary operations (`+`,`-`,`==`, `/` etc.) with function calls. This decreases code readability, as you constantly need to look up the definition of the extra functions. Here's an example:
    
    ```
    // An example of proxy function usage 
     
    az = {}; 
     
    // '+' operation proxy function 
    az.pNrrD = function (aB, aC) { 
    return aB + aC; 
    }; 
    // '-' operation proxy function 
    az.aZawd = function (aB, aC) { 
    return aB - aC; 
    }; 
    // '===' operation proxy function 
    az.fhjsC = function (aB, aC) { 
    return aB === aC; 
    }; 
     
    /* ... */ 
     
    // Equivalent to ((1 + 3) - 4) === 0 
     
    az.fhjsC(az.aZawd(az.pNrrD(1, 3), 4), 0);
    ```
    
-   **Atomic Operations**. Especially in the main/second challenge script, Cloudflare converts simple strings or numeric literals into long, convoluted expressions taking advantage of the atomic parts of javascript (unary expression, math operations, and empty arrays). This technique is very reminiscent of [JSFuck](http://www.jsfuck.com/). Example:
    
    ```
     // Believe it or not, this is equivalent to: 
    // a = 1.156310815361637 
    a = 
    (!+[] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    [] + 
    (!+[] + !![] + !![] + !![]) + 
    -~~~[] + 
    (!+-[] + +-!![] + -[]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![] + !![] + !![]) + 
    (!+[] + !![] + !![]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![] + !![] + !![] + !![]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![] + !![] + !![]) + 
    -~~~[]) / 
    +( 
    !+[] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    !![] + 
    [] + 
    -~~~[] + 
    (!+[] + !![] + !![]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![] + !![] + !![]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![] + !![]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![]) + 
    (!+[] + !![] + !![] + !![] + !![] + !![]) + 
    (!+[] + !![] + !![]) 
    );
    ```
    

What makes developing a Cloudflare bypass non-trivial is its script's obfuscation and dynamic nature. Each time you enter a Cloudflare waiting room, you're going to be faced with new challenge scripts.

If you want to create your own Cloudflare bypass, you'll need some highly-specialized skills. The obfuscation of Cloudflare's challenge scripts is good enough that you can't just throw it in a general-purpose deobfuscator and get a readable output. You'll need to create a custom deobfuscator capable of dynamically parsing and transforming each new Cloudflare challenge script into human-readable code. _Hint: Try manipulating the script's abstract syntax tree_

Once you've made a working dynamic deobfuscator, you'll be able to understand better all the checks Cloudflare's anti-bot performs on your browser and how to replicate the challenge-solving process.

In the next step, we'll analyze some active bot detection implementations from the deobfuscated Cloudflare script. Let's get to it!

### Step 4: analyzing the deobfuscated script

Remember those cryptic payloads and base64 encoded response bodies? Well, now we can understand how they work!

#### Cloudflare's encryption

Recall this code snippet, where we determined that the response text was being used to evaluate the main/second challenge script:

```
// Note: aE = new XMLHttpRequest(), an XMLHttpRequest instance initialized earlier in the script 
new window.Function(aB.pgNsC(ax, aE.responseText))();
```

The deobfuscated version looks like this:

```
// Note: aE = new XMLHttpRequest(), an XMLHttpRequest instance initialized earlier in the script 
new window.Function(ax(aE.responseText))();
```

In the end, `ab.pgNsC` was just a proxy wrapper for the `ax` function. The deobfuscated `ax` function looks like this:

```
ax = function (ay) { 
var aF; 
var aE = window._cf_chl_opt.cRay + "_" + 0; 
aE = aE.replace(/./g, function (_, aH) { 
32 ^= aE.charCodeAt(aH); 
}); 
ay = window.atob(ay); 
var aD = []; 
for ( 
var aB = -1; 
!isNaN((aF = ay.charCodeAt(++aB))); 
aD.push(String.fromCharCode(((aF & 255) - 32 - (aB % 65535) + 65535) % 255)) 
) {} 
return aD.join(""); 
};
```

Can you guess what this function does? It's a decryption function!

Cloudflare encrypts the main/second challenge script with a cipher. Then, after the first `POST` request to solve the initial challenge, Cloudflare returns the encrypted second challenge script.

To actually execute the challenge, it's decrypted into a string with the `ax` function using `window._cf_chl_opt.cRay` as the decryption key. That string is then passed into the [Function constructor](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Function/Function) to create a new function and executed with `()`!

We also previously discussed Cloudflare's [active bot detection techniques](https://www.zenrows.com/blog/bypass-cloudflare#cloudflare-active-bot-detection-techniques). Now, we can revisit a few of them to see their implementations!

#### CAPTCHAs

Here, we can see how Cloudflare loads an hCaptcha instance:

```
o["_cf_chl_hload"] = function () { 
o["_cf_chl_hloaded"] = true; 
}; 
 
q["push"](function (aD, aC, aA, az, ay) { 
aA = false; 
o["setTimeout"](aB, 3500); 
aC = p["createElement"]("script"); 
aD = "https://cloudflare.hcaptcha.com/1/api.js?endpoint=https%3A%2F%2Fcloudflare.hcaptcha.com&assethost=https%3A%2F%2Fcf-assets.hcaptcha.com&imghost=https%3A%2F%2Fcf-imgs.hcaptcha.com&"; 
o["_cf_chl_hlep"] = "2"; 
aC["src"] = aD + "render=explicit&recaptchacompat=off&onload=_cf_chl_hload"; 
aC["onerror"] = aB; 
p["getElementsByTagName"]("head")[0]["appendChild"](aC); 
 
function aB(aI, aH, aG, aF, aE) { 
if (o["_cf_chl_hloaded"]) { 
return; 
} 
 
if (aA) { 
return; 
} 
/* ... */ 
} 
});
```

#### Canvas fingerprinting

In this snippet, Cloudflare is creating an array of canvas fingerprinting functions for use later on in the script:

```
S = [ 
/* ... */ 
function (a3, a4, a5, af, ae, ad, ac, ab, aa, a9, a8, a7, a6) { 
a3.shadowBlur = 1 + O(L); 
a3.shadowColor = R[O(R.length)]; 
a3.beginPath(); 
ad = a4.width / H; 
ae = a4.height / H; 
a8 = ad * a5 + O(ad); 
a9 = O(ae); 
a3.moveTo(a8 | 0, a9 | 0); 
af = a4.width / 2 + O(a4.width); 
aa = O(a4.height / 2); 
ac = a4.width - a8; 
ab = a4.height - a9; 
a3.quadraticCurveTo(af | 0, aa | 0, ac | 0, ab | 0); 
a3.stroke(); 
return true; 
}, 
/* ... */ 
];
```

#### Timestamp tracking

There are many places in the script where Cloudflare queries the browser for timestamps. Here's an example:

```
k = new Array(); 
pt = -1; 
 
/* ... */ 
if (window.performance.timing && window.performance.timing.navigationStart) { 
ns = window.performance.timing.navigationStart; 
} 
for (var j = 0; j < 10; j++) { 
k.push(Date.now() - ns - pt); 
}
```

#### Event tracking

Here, we can see that Cloudflare adds `EventListener`s to the webpage to track mouse movements, mouse clicks, and key presses.

```
function x(aE, aD, aC, aA, az, ay) { 
aA = false; 
aE = function (aF, aG, aH) { 
p.addEventListener 
? p.addEventListener(aF, aG, aH) 
: p.attachEvent("on" + aF, aG); 
}; 
aE("keydown", aB, aD); 
aE("pointermove", aB, aD); 
aE("pointerover", aB, aD); 
aE("touchstart", aB, aD); 
aE("mousemove", aB, aD); 
aE("click", aB, aD); 
function aB() { 
/* .. */ 
} 
}
```

#### Automated browser detection

Here are a few of the checks Cloudflare has to detect the use of popular automated browsing libraries:

```
function _0x15ee4f(_0x4daef8) { 
return { 
/* .. */ 
wb: !(!_0x4daef8.navigator || !_0x4daef8.navigator.webdriver), 
wp: !(!_0x4daef8.callPhantom && !_0x4daef8._phantom), 
wn: !!_0x4daef8.__nightmare, 
ch: !!_0x4daef8.chrome, 
ws: !!( 
_0x4daef8.document.__selenium_unwrapped || 
_0x4daef8.document.__webdriver_evaluate || 
_0x4daef8.document.__driver_evaluate 
), 
wd: !(!_0x4daef8.domAutomation && !_0x4daef8.domAutomationController), 
}; 
}
```

#### Sandboxing detection

In this snippet, the script checks if it's running in a NodeJS environment by searching for the node-only `process` object:

```
(function () { 
SGPnwmT[SGPnwmT[0]] -= +( 
(Object.prototype.toString.call( 
typeof globalThis.process !== "undefined" ? globalThis.process : 0 
) === 
"[object process]") === 
false 
); 
/* ... */ 
});
```

To detect any modification of native functions (ex., [monkey patching](https://www.audero.it/blog/2016/12/05/monkey-patching-javascript/)), Cloudflare executes `toString` on them to check if they return the `"[native code]"` or not.

```
c = function (g, h) { 
return ( 
h instanceof g.Function && 
g.Function.prototype.toString.call(h).indexOf("[native code]") > 0 
); 
};
```

### Step 5: putting it all together

Phew, it's been quite the journey so far! We know, that was **a lot** to take in. Let's take a short break and reflect on what you've learned so far:

-   The purpose of Cloudflare's anti-bot
-   The active and passive bot detection techniques Cloudflare uses
-   What is the Cloudflare waiting room/challenge page
-   How to reverse engineer the Cloudflare waiting room's request flow
-   How to deobfuscate the Cloudflare challenge scripts
-   How Cloudflare implements bot detection techniques in their Javascript challenge

Now, the last step is to put all of that knowledge together and bypass Cloudflare!

## How to bypass Cloudflare

We already mentioned that it's not an easy feat, but how do I bypass Cloudflare protection? To bypass Cloudflare, you'll need to combine all the knowledge you've gained from the previous sections.

As you know by now, Cloudflare has **two bot detection methods**: **passive fingerprinting** and **active bot detection** (_through their JavaScript challenge_). **To bypass Cloudflare, you sneak under the radar of both of them.** To get you started, here are some tips for each.

### Bypassing Cloudflare passive bot detection

-   **Use high-quality proxies.** To disguise your scraper as a legitimate user, use residential proxies. Datacenter proxies and VPNs are easily detected by Cloudflare and are classified as suspicious traffic. Additionally, too many requests from a single IP address can lead to blocks, so be sure to rotate out your proxies each session to avoid that.
-   **Mimic your browser's headers.** Make your scraper's requests look as real as possible by making sure to send all the HTTP headers from the original request. **This includes having valid cookie headers for each request!**
-   **Match a whitelisted fingerprint**. If you decide to go the browser automation route, your scraper might fulfill this requirement by default. But, only provided that you use the **exact user agent and browser version the library is built upon**. This becomes **a lot more tedious when developing a fully request-based scraper.** You'll need to capture and analyze packets from the browsers you intend to impersonate. Your selection of programming languages is limited. It must have **enough low-level access to control all the components to Cloudflare's TLS and HTTP/2 fingerprinting specification**, so you can **match a browser 1:1**.

Remember, passive bot detection is Cloudflare's first layer of defense. If you want to bypass Cloudflare, you can't neglect this step.

If your activity is labeled suspicious by their passive bot protection system, you'll be blocked immediately. On the contrary, slipping past them might even allow you to skip over the active bot protection checks.

### Bypassing Cloudflare active bot detection

-   **Reconstruct the challenge-solving logic**. This requires an expert understanding of the Cloudflare waiting room's internals. Study its request flow and deobfuscated script. You'll need to figure out _exactly_ **what checks Cloudflare performs, in what order they're executed, and how you can bypass them**. You also need to **replicate the encryption and decryption of Cloudflare's various payloads**. This is the most difficult part of creating a bypass since the Cloudflare challenge scripts are dynamic. **Every session might even require you to deobfuscate a new script on the fly**, to parse specific values for use in your solver.
-   **Collect Real Device Data**. Even if you understand exactly how they're made, **some fingerprints are too impractical to attempt impersonating**. For example, Cloudflare's Canvas fingerprinting. Unlike a TLS or HTTP/2 fingerprint, it relies heavily on moving parts from both software _and_ hardware. The functionality of hardware components is way too advanced to try and imitate and not something you want to spend all your time designing for a scraping project. Instead, consider collecting fingerprint data from real users' devices. Then, you can inject this data into your solver whenever it needs to be used. But, you won't get far with just a few. Your best option would be to **host a collector on a high-traffic webpage** to ensure you have enough devices to avoid looking suspicious to Cloudflare's machine learning systems.
-   **Use Automated Browsers / Sandbox The Script** If you want to abstract some of the challenge-solving logic, you might consider directly executing the Cloudflare JavaScript challenges. This could be in-browser using automated tooling or by emulating a browser in a sandbox such as JSDOM. **The downside to this approach is the performance**. Running or emulating a browser environment will be much slower and compute-expensive than a request/algorithm-based challenge solver. Also, recall that Cloudflare has **checks for automated browsers and sandboxing.** To bypass them, you first must understand which ones exist and how they work. **So, sandboxed or not, you won't be able to skip deobfuscating the Cloudflare challenge scripts!**

If you've gotten this far, great job! You're now familiar with the process of making a solver for Cloudflare's antibot challenge.

Don't fret if you found yourself feeling lost during the process. We get it, bypassing any antibot can feel like a daunting task. **But that doesn't mean you should give up on your scraping project!**

Bypassing Cloudflare from scratch is a complicated task, and there aren't any shortcuts if you plan to do it yourself. **But, it doesn't have to be this difficult! Sometimes, it's best to have someone else take care of it for you.**

## The easiest way to bypass Cloudflare

Most of the time, it's just not practical to spend massive amounts of time, energy, and money developing and maintaining your own solver.

**[ZenRows](https://www.zenrows.com/) is designed to bypass Cloudflare and all other antibot solutions.** Stop worrying about the intricacies of detection techniques, dynamic obfuscation, challenge solving, or updates. Offering both API and proxy modes, **ZenRows can be seamlessly integrated into any of your scraping projects.**

Focus on your data scraping vision, and let ZenRows handle the rest.

## Conclusion

Congratulations on sticking with us to the end! We know it was a lengthy read, but Cloudflare's high complexity made it a necessity.

Thanks for reading! We hope this guide has helped you learn valuable knowledge about Cloudflare's bot detection techniques, how to reverse engineer them, and how to ultimately bypass them. The methodology you learned today isn't just Cloudflare-specific either: you can go out and refer back to it to help you bypass other antibots!

Speaking of other antibots, [click here to read about how to bypass Akamai's Bot Manager](https://www.zenrows.com/blog/bypass-akamai).

Thanks for reading! We hope that you found this guide helpful. You can [sign up for free](https://www.zenrows.com/register), try ZenRows, and let us know any questions, comments, or suggestions.

Did you find the content helpful? Spread the word and share it on [Twitter](https://twitter.com/share?text=%E2%9C%8D%F0%9F%8F%BBLearn%20how%20to%20bypass%20Cloudflare%20Bot%20Management.%20You%27ll%20add%20evasions%20to%20skip%20blocks%20by%20understanding%20how%20it%20works%20and%20what%20sensor%20data%20it%20sends.%F0%9F%94%A5&url=https%3A%2F%2Fwww.zenrows.com%2Fblog%2Fbypass-cloudflare%2F%3Futm_source%3Dtwitter%26utm_medium%3Dshared%26rd%3D221003184), [LinkedIn](https://www.linkedin.com/sharing/share-offsite/?url=https%3A%2F%2Fwww.zenrows.com%2Fblog%2Fbypass-cloudflare%2F%3Futm_source%3Dlinkedin%26utm_medium%3Dshared%26rd%3D1838844314), or [Facebook](https://www.facebook.com/sharer/sharer.php?u=https%3A%2F%2Fwww.zenrows.com%2Fblog%2Fbypass-cloudflare%2F%3Futm_source%3Dfacebook%26utm_medium%3Dshared%26rd%3D1858761680).

**Frustrated that your web scrapers are blocked once and again?** ZenRows API handles rotating proxies and headless browsers for you.

[Try for FREE](https://www.zenrows.com/register)