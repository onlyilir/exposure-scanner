# Pause HTTPS scanning for a check-up

Many antivirus programs open secure (https) connections to check them for threats. To do that they swap the website's certificate for one of their own. A website check-up run on that computer then sees the antivirus's certificate instead of the site's, so the certificate part of the report stays empty and the report says **Not ready to send**.

You do not need to turn your antivirus off. Turn off **only its HTTPS scanning feature** for the check-up, then turn it back on. File scanning and real-time protection keep working the whole time.

The desktop app shows the steps for the antivirus it finds on your PC (from Windows Security Center) on the New check-up page, and all of them under **How it works**.

| Antivirus | Where the setting is | Vendor help |
|---|---|---|
| Norton 360 | Security › Advanced Security › Web › Safe Web › Settings › turn off **HTTPS scanning** | Norton 360 for Windows |
| Avast | ☰ Menu › Settings › Protection › Core Shields › Configure shield settings › Web Guard (Web Shield) › untick **Enable HTTPS scanning**. Newer versions: Settings › Scam Guardian › Web Guard | [Avast](https://support.avast.com/en-ww/article/190/) |
| AVG | ☰ Menu › Settings › Basic protection › Web Shield › untick **Enable HTTPS scanning** | [AVG](https://support.avg.com/SupportArticleView?l=en&urlname=use-avg-antivirus-https-scan) |
| Kaspersky | Settings › Security settings › Network settings › Encrypted connections scan › **Do not scan encrypted connections** | [Kaspersky](https://support.kaspersky.com/kaspersky-for-windows/21.21/157530) |
| ESET | F5 (Advanced setup) › Protections › SSL/TLS › switch off **Enable SSL/TLS** | [ESET](https://support.eset.com/en/kb3126-disable-ssl-filtering-in-eset-windows-products) |
| Bitdefender | Protection › Online Threat Prevention › Settings › switch off **Encrypted web scan** | [Bitdefender](https://www.bitdefender.com/consumer/support/answer/28557/) |

Menu names change between versions; the setting's own name (in bold) is the thing to look for.

- **Microsoft Defender**, built into Windows, does not swap website certificates, so it needs no change.
- **Other antivirus or security apps:** in their web protection settings, look for HTTPS scanning, SSL/TLS scanning, encrypted connection scanning or encrypted web scan.
- **Work networks and company VPNs** can do the same in the company firewall (for example Zscaler). That cannot be changed on your PC: run the check-up from another network.
- **Firewall prompts:** if your firewall asks whether `scanner.exe` may use the internet, allow it.

How the scanner notices: it compares the certificate's issuer with the names these products give their own certificates (for example "Avast Web/Mail Shield Root", "ESET SSL Filter CA"). When it finds one, the report names it and asks you to pause that feature and run the check again.
