// HTTPS scanning: many antivirus programs open secure (https) connections to scan them, and to do
// that they swap the website's certificate for one of their own. The check-up then sees the
// antivirus's certificate instead of the site's. Only that one feature has to be paused for the
// check; the antivirus itself stays on. Steps come from each vendor's own help pages:
//   Avast       https://support.avast.com/en-ww/article/190/
//   AVG         https://support.avg.com/SupportArticleView?l=en&urlname=use-avg-antivirus-https-scan
//   Kaspersky   https://support.kaspersky.com/kaspersky-for-windows/21.21/157530
//   ESET        https://support.eset.com/en/kb3126-disable-ssl-filtering-in-eset-windows-products
//   Bitdefender https://www.bitdefender.com/consumer/support/answer/28557/
//   Norton      Norton 360 for Windows (Safe Web settings; checked on a real install)
// Menu names change between versions, so every entry also names the setting itself.
using System;
using System.Collections.Generic;
using System.Linq;

namespace ExposureScanner
{
    static class HttpsScanning
    {
        public class Product
        {
            public string Match;   // lowercase text in the product or certificate issuer name
            public string Name;
            public string Steps;
        }

        public static readonly Product[] Products =
        {
            new Product { Match = "norton", Name = "Norton 360",
                Steps = "Open Norton › Security › Advanced Security › Web › Safe Web › Settings, then turn off HTTPS scanning." },
            new Product { Match = "avast", Name = "Avast",
                Steps = "Open Avast › ☰ Menu › Settings › Protection › Core Shields › Configure shield settings › Web Guard (Web Shield), then untick Enable HTTPS scanning. Newer versions: Settings › Scam Guardian › Web Guard." },
            new Product { Match = "avg", Name = "AVG",
                Steps = "Open AVG › ☰ Menu › Settings › Basic protection › Web Shield, then untick Enable HTTPS scanning." },
            new Product { Match = "kaspersky", Name = "Kaspersky",
                Steps = "Open Kaspersky › Settings › Security settings › Network settings › Encrypted connections scan, then choose Do not scan encrypted connections." },
            new Product { Match = "eset", Name = "ESET",
                Steps = "Open ESET and press F5 (Advanced setup) › Protections › SSL/TLS, then switch off Enable SSL/TLS." },
            new Product { Match = "bitdefender", Name = "Bitdefender",
                Steps = "Open Bitdefender › Protection › Online Threat Prevention › Settings, then switch off Encrypted web scan." },
        };

        public const string Why =
            "Many antivirus programs open secure (https) connections to check them for threats. To do that they swap " +
            "the website's certificate for their own, so the check-up sees the antivirus's certificate instead of the " +
            "site's, and the certificate part of the report stays empty. Turn off only that feature, not your antivirus: " +
            "file scanning and real-time protection keep working.";
        public const string Defender =
            "Microsoft Defender, built into Windows, does not swap website certificates, so it needs no change.";
        public const string Other =
            "Other antivirus or security apps: in their web protection settings, look for HTTPS scanning, SSL/TLS " +
            "scanning, encrypted connection scanning or encrypted web scan, and turn off only that.";
        public const string Work =
            "On a work network or company VPN, the company's firewall may do the same (for example Zscaler). That cannot " +
            "be changed on your PC: run the check-up from another network.";
        public const string Firewall =
            "If your firewall asks whether scanner.exe may use the internet, allow it: the check-up needs to reach the website.";
        public const string After =
            "Turn HTTPS scanning back on when the check-up is done. If you forget a setting, the report says Not ready to send.";

        // Antivirus products registered with Windows Security Center ("Norton 360", "Windows Defender").
        public static List<string> Installed()
        {
            var names = new List<string>();
            try
            {
                using (var s = new System.Management.ManagementObjectSearcher(
                           @"root\SecurityCenter2", "SELECT displayName FROM AntiVirusProduct"))
                    foreach (System.Management.ManagementBaseObject o in s.Get())
                    {
                        string n = o["displayName"] as string;
                        if (!string.IsNullOrEmpty(n) && !names.Contains(n))
                            names.Add(n);
                    }
            }
            catch (Exception) { } // Windows Server has no Security Center; a blocked query is not an error
            return names;
        }

        public static Product Find(string name)
        {
            string n = (name ?? "").ToLowerInvariant();
            return Products.FirstOrDefault(p => n.Contains(p.Match));
        }

        public static bool IsDefender(string name)
        {
            string n = (name ?? "").ToLowerInvariant();
            return n.Contains("defender");
        }

        // One line for the check-up form: what to do on this PC.
        public static string AdviceFor(List<string> installed)
        {
            var known = installed.Select(Find).Where(p => p != null).Distinct().ToList();
            if (known.Count > 0)
                return string.Join(" ", known.Select(p => "On this PC: " + p.Name + ". " + p.Steps));
            if (installed.Count > 0 && installed.All(IsDefender))
                return Defender + " Other security apps or a work network can still do it: see How it works.";
            return "How it works lists the steps for Norton, Avast, AVG, Kaspersky, ESET and Bitdefender.";
        }
    }
}
