I don’t know what I did wrong, but I’ve angered one of the titans of the internet! For the last six days, my home internet connection has been partially broken. Some apps and many websites either load slowly, partially, or not at all. Everywhere I go, I’m greeted by the same blockade message from Cloudflare.

Cloudflare is the market leader in shielding public websites from targeted traffic-saturation attacks, page load time acceleration, and Content Delivery Network (CDN) services. The company plays a massive role in delivering everyday internet services. Roughly one in three of the top one-million websites is shielded and accelerated through Cloudflare’s massive global data centers, according to data from analytics firm BuiltWith.

Among other methods, Cloudflare uses a browser-challenge page to detect and thwart malicious and unauthorized bots. The page tests the capabilities of your web browser and tries to figure out whether you’re human. The page can be fully automated and only slows down your browsing. However, sometimes it includes a CAPTCHA challenge that prompts you to identify letters and numbers, or images.

For whatever reason, I must have done something that angered Cloudflare. Just about every website I visited from my home internet connection would result in a challenge page. The blockade lasted six days! My partner and I got uncomfortably acquainted with Cloudflare’s market dominance.

We luckily weren’t pestered by too many CAPTCHAs. However, the average webpage load time fell from the normal ≤ 4 seconds to 20–80 seconds. It felt like we’d been transported back to an earlier era with unbearably slow internet.

I’m unsure if my IP reputation was classified with a high bot score (likely automated requests) or given a high threat score (likely malicious request). Cloudflare doesn’t offer end-users any way to dispute or even check their IP reputation scores. The company doesn’t offer end-users any support at all. Everything is automated.

Unfortunately, not every web request can run the Cloudflare challenge page. Many websites only use Cloudflare with a secondary domain name that is only used to serve images, stylesheets, scripts, and other assets. So, while I could quickly load the main webpage, it often wouldn’t work properly because it couldn’t load critical assets.

Websites don’t just serve webpages and their assets, though. Roughly half my podcasts refused to update in my podcast app. The app didn’t know what to do when presented with a browser-challenge page instead of the podcast syndication feed files it expected. It just gave up and threw up error messages.

Plenty of other apps stopped working too. My partner still uses the [Bitwarden password manager](https://www.ctrl.blog/entry/bitwarden-3m-update.html "“Update after 3 months with Bitwarden”"). It wouldn’t let them log in to their account to access their password vault because the login process was interrupted by a Cloudflare challenge page.

I’m using an offline password vault app called [KeePassXC](https://www.ctrl.blog/entry/keepass-vs-bitwarden-server.html "“Why KeePass instead of self-hosting Bitwarden”"). I must admit that I was a bit gleeful when the effort I’ve put into not having to trust and rely on a hosted password manager finally paid off!

To be fair to Cloudflare, apps and podcasts aren’t allowed on its free product tier. Website administrators can configure exceptions in their Cloudflare accounts. They can mark certain web addresses as asset addresses and have them always bypass the challenge page. This option isn’t available to customers on the free tier, however.

Well into the second day of Cloudflare’s blockade of my home internet connection, Google Search also began blocking requests. It required me to resolve a CAPTCHA challenge for every other search. This luckily only lasted a day.

Cloudflare shares IP reputation data with partners like Google, coordinated through a program called the Bandwidth Alliance. So, my original offense might not even have been against Cloudflare. It might have received the reputation data from a partner, and it just propagated through the Bandwidth Alliance network.

It might not even have been a problem that originated from my IP address! One of my IP neighbors might have done something stupid and negatively affected the whole network neighborhood for a couple of days!

I had a terrible experience online for almost a week before everything cleared up. Automated decisions and backroom data-sharing had tossed a wrench into my entertainment, productivity, and online life.

Section 4 of the General Data Protection Regulation (GDPR) grants Europeans the right to object to automated individual decision-making, including profiling. There’s one paragraph from the regulation in particular that bears repeating:

> \[Europeans\] shall have the right not to be subject to a decision based solely on automated processing, including profiling, which produces legal effects concerning \[them\] or similarly significantly affects \[them\].

GDPR, Article 4, Paragraph 1

I’d say my experiences fit that description head-on. Cloudflare or one of its partner’s systems made an entirely automated decision that significantly negatively affected my online life. Come to think of it, an IP address is considered as a potentially personally identifying identifier. I’ve never agreed to data-sharing with the Bandwidth Alliance!

Unfortunately — and probably for the best — the GDPR also makes exceptions for data-sharing, processing, and — although I couldn’t find the verbatim — automated-decision making for the purposes of ensuring network and information security.

I’m no lawyer, but I probably don’t have a right to object to being misclassified as a bot by a security system. Even though it ruined my internet experience.

I don’t know what eventually cleared my IP reputation, but Cloudflare stopped blocking requests from my IP after six days. On day three, I install Cloudflare’s [Privacy Pass browser extension](https://privacypass.github.io/) on all my desktop devices. The browser extension uses the same protocol as Apple and Cloudflare are working on integrating into MacOS and iOS.

The extension provides, what Cloudflare claims, is a privacy-preserving alternative to resolving CAPTCHAs on its challenge pages. This might have affected the situation, but again, I have no insight into Cloudflare’s automated decision-making.

My run-in against Cloudflare’s “security” blockade was an incredibly frustrating experience. I felt truly powerless against an unknowable algorithm that sat somewhere out there and decided to block my free movement on the web.

I can only imagine how painful it must be to try and develop a web crawling bot these days. It doesn’t matter if your intentions are good and your bot polite. It’ll probably be blocked everywhere sooner rather than later.