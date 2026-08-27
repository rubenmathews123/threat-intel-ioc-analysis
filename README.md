# Threat Intelligence & IOC Analysis

A set of short investigations where I take real indicators of compromise (emails, URLs, IPs, file hashes) and work them the way a SOC analyst would: pull out the indicators, check them against threat intelligence, and reach a verdict with a recommended action. Each case follows the same structure so the method stays consistent.

Tools used: VirusTotal, AbuseIPDB, URLhaus, PhishTank, and manual email header analysis.

A note on method: I try not to rely on any single tool. Threat intel results are often messy, aged, or ambiguous in the real world, so each verdict is built from the weight of combined evidence rather than one score.

---

## Case 1: Phishing Email Impersonating Bradesco (Email Header Analysis)

**Summary:** A phishing email impersonating the Brazilian bank Bradesco and its Livelo rewards program, using an expiring-points lure. This case focuses on email header and authentication analysis.

**IOCs:**
- From domain: atendimento.com.br
- Real sending IP: 137.184.34.4
- Origin host: ubuntu-s-1vcpu-1gb-35gb-intel-sfo3-06 (a DigitalOcean cloud server)
- Embedded URL: blog1seguimentmydomaine2bra.me (offline at time of analysis)

**Investigation:**

Reading the Received headers from the bottom up, the email originated on a throwaway DigitalOcean Ubuntu server, not on any Bradesco infrastructure. The lowest Received line shows the message being created on that server (from userid 0, i.e. root), then handed to Microsoft's mail protection at IP 137.184.34.4.

![Email headers showing failed authentication and throwaway origin server](https://github.com/rubenmathews123/threat-intel-ioc-analysis/blob/main/screenshots/bradesco-headers.png)

Email authentication failed across the board:
- SPF returned temperror (a DNS timeout meant the sender could not be verified)
- DKIM was none (the message was not signed at all, which a real bank would never skip)
- DMARC returned temperror and composite authentication failed (compauth=fail)

The embedded link used a gibberish, Brazil-themed lookalike domain on a .me TLD, hidden behind a "Resgatar Agora" (Redeem Now) button.

![Decoded email body showing the phishing link behind the Redeem Now button](https://github.com/rubenmathews123/threat-intel-ioc-analysis/blob/main/screenshots/bradesco-phishing-link.png)

Checking the two remaining indicators returned inconclusive results, purely because the campaign is old:
- The sending IP (137.184.34.4) traces to a DigitalOcean cloud server. On AbuseIPDB and VirusTotal it showed a low current abuse score, and the few reports present post-date the email and relate to unrelated activity (port scanning, brute force). This is consistent with cloud IP recycling: the address was likely reassigned to other tenants after this 2023 campaign, so its present reputation says little about the original phishing use.
- The embedded URL was already offline and returned no detections on VirusTotal. This reflects the phishing site being taken down since the campaign, not that the link was ever safe.

**Analysis:** The header evidence is conclusive. An email claiming to be a major bank that is unsigned, fails authentication, and originates from a cheap cloud server is forged. Two of the indicators (IP reputation and the live URL scan) came back inconclusive only because the campaign is old, and the verdict does not depend on them. Absence of detection is not evidence of safety; the failed authentication and the throwaway origin server are conclusive on their own.

**Verdict:** Phishing. High confidence.

**Recommended action:** Block the sender domain and sending IP, remove the email from any affected inboxes, and warn users about points-expiry lures impersonating the bank.

---

## Case 2: Live Mirai Malware Distribution URL

**Summary:** A live URL actively distributing Mirai malware (an IoT botnet family) as a Linux executable.

**IOCs:**
- URL: http://85.12.237.201:41070/i
- Host IP: 85.12.237.201
- Payload file hash (SHA256): 12013662c71da69de977c04cd7021f13a70cf7bed4ca6c82acbc100464d4b0ef
- Malware family: Mirai

**Investigation:**

Found on URLhaus, flagged as an active malware-distribution URL, online and serving a payload. The URL is a raw IP address with a port rather than a domain, which is typical of malware infrastructure talking to infected machines rather than fooling humans. The payload is an ELF (Linux) binary tagged as Mirai, consistent with IoT botnet recruitment.

VirusTotal returned 18 of 92 vendors flagging the URL as malicious or malware, including BitDefender, ESET, Fortinet, G-Data, Sophos, VIPRE, and Dr.Web. VirusTotal's crowdsourced context also attributed the URL directly to Mirai, describing it as malware that builds a botnet of Linux devices to launch large-scale network attacks, primarily targeting consumer devices like IP cameras and home routers.

![VirusTotal detections and Mirai attribution for the malware URL](https://github.com/rubenmathews123/threat-intel-ioc-analysis/blob/main/screenshots/mirai-malware-virustotal.png)

**Analysis:** This is malware distribution rather than phishing, included to show IOC analysis across threat types. The bare IP and port, the Linux ELF payload, and the Mirai attribution all point to a botnet node recruiting vulnerable IoT devices. The distinction from phishing matters: phishing targets humans with lookalike domains, while this targets machines directly.

**Verdict:** Malicious (malware distribution). High confidence.

**Recommended action:** Block the IP and URL at the firewall and proxy, and hunt for any internal devices that may have already connected to it.

---

## Case 3: Live Phishing Site Impersonating Itau (Brazilian Bank)

**Summary:** A live phishing site impersonating Itau Unibanco with a rewards-points lure, confirmed malicious by a wide range of security vendors.

**IOCs:**
- URL: https://itau.maispontos.app/index.html
- Domain: maispontos.app (real brand "itau" used only as a subdomain)
- Host IP: 74.179.80.31
- Impersonated brand: Itau (largest bank in Brazil)

**Investigation:**

VirusTotal returned 12 of 92 vendors flagging the URL, with many explicitly labeling it Phishing, including Google Safe Browsing, Kaspersky, BitDefender, ESET, Sophos, and G-Data. The site returned HTTP 200, meaning it was live and serving the phishing page at the time of analysis.

![VirusTotal detections for the Itau phishing URL](https://github.com/rubenmathews123/threat-intel-ioc-analysis/blob/main/screenshots/itau-phishing-virustotal.png)

The domain structure is the classic impersonation trick: the trusted brand name (itau) is placed as a subdomain on an attacker-controlled domain (maispontos.app, which translates to "more points"). The Details tab confirmed the hosting IP and domain information.

![VirusTotal details tab for the Itau phishing domain](https://github.com/rubenmathews123/threat-intel-ioc-analysis/blob/main/screenshots/itau-phishing-details.png)

**Analysis:** The evidence here is clean and convergent, unlike Case 1. Multiple independent and authoritative vendors agree the URL is phishing, the site was live, and the domain structure corroborates the impersonation. A low raw count (12 of 92) is still conclusive when the vendors flagging it are reputable and phishing-specialized, and when the count includes Google Safe Browsing.

**Verdict:** Phishing. High confidence.

**Recommended action:** Block the domain and URL, submit for takedown, and alert customers to the points-scam pattern.

---

## What I took away from this

The most useful lesson across these cases was that tool results are rarely clean. One URL was dead (no detections, but still clearly malicious from its headers), one investigation of a suspicious-looking bank email in my own spam folder turned out to be legitimate marketing, and only the live cases lit up clearly. A verdict comes from weighing all the evidence together and knowing why a result looks the way it does, not from trusting a single score. Learning not to cry wolf on a legitimate email was as valuable as catching the real ones.
