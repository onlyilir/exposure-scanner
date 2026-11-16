// Security data updater: downloads public vulnerability and end-of-life lists and writes the
// scanner's local database, vulndb.txt (tab-separated lines that the C engine reads, see
// src/vulndb.h). Every source is free and needs no key:
//   WordPress.org version table  https://api.wordpress.org/core/stable-check/1.0/
//   NIST NVD (CVEs by product)   https://services.nvd.nist.gov/rest/json/cves/2.0
//   OSV.dev (GitHub advisories)  https://api.osv.dev/v1/query
//   CISA KEV (holes in active use) https://www.cisa.gov/known-exploited-vulnerabilities-catalog
//   endoflife.date               https://endoflife.date/docs/api
// Only product names are sent. Nothing about the user or their checks leaves the PC.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading;
using System.Web.Script.Serialization;

namespace ExposureScanner
{
    static class VulnData
    {
        public const string FileName = "vulndb.txt";

        // the refreshed copy; scanner.exe prefers it over the one shipped next to it
        public static string UserFile
        {
            get
            {
                return Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                                    "Exposure Scanner", FileName);
            }
        }

        // product id -> NVD CPE "vendor:product" (CVE version ranges, CVSS)
        static readonly string[][] NvdProducts =
        {
            new[] { "wordpress", "cpe:2.3:a:wordpress:wordpress" },
            new[] { "joomla", "cpe:2.3:a:joomla:joomla\\!" },
            new[] { "drupal", "cpe:2.3:a:drupal:drupal" },
        };

        // product id -> OSV ecosystem + package (GitHub-reviewed advisories with severity)
        static readonly string[][] OsvProducts =
        {
            new[] { "nextjs", "npm", "next" },
            new[] { "ghost", "npm", "ghost" },
            new[] { "drupal", "Packagist", "drupal/core" },
            new[] { "magento", "Packagist", "magento/community-edition" },
            new[] { "joomla", "Packagist", "joomla/joomla-cms" },
        };

        // product id -> endoflife.date product
        static readonly string[][] EolProducts =
        {
            new[] { "php", "php" }, new[] { "nginx", "nginx" }, new[] { "apache", "apache-http-server" },
            new[] { "openssl", "openssl" }, new[] { "windows-server", "windows-server" },
            new[] { "ubuntu", "ubuntu" }, new[] { "debian", "debian" }, new[] { "centos", "centos" },
            new[] { "rhel", "rhel" }, new[] { "rocky", "rocky-linux" }, new[] { "alma", "almalinux" },
            new[] { "amazon-linux", "amazon-linux" }, new[] { "wordpress", "wordpress" },
            new[] { "drupal", "drupal" }, new[] { "joomla", "joomla" }, new[] { "magento", "magento" },
            new[] { "nextjs", "nextjs" }, new[] { "nodejs", "nodejs" }, new[] { "dotnetfx", "dotnetfx" },
        };

        class Vuln
        {
            public string Product, Id, Severity = "unknown", Score = "-", Url, Summary = "";
            public List<string> Groups = new List<string>(); // ">=1.0,<1.2" per affected range
            public SortedSet<string> Fixed = new SortedSet<string>(StringComparer.Ordinal);
            public List<string> Aliases = new List<string>(); // other ids of the same hole (CVE, GHSA, related)
            public bool Kev;
        }

        // `ExposureScanner.exe --update-data [--out <file>]`: 0 written, 1 failed (see the log)
        public static int Cli(string outFile)
        {
            string log = Path.Combine(Path.GetTempPath(), "ExposureScanner-update.log");
            try
            {
                int n = Update(outFile ?? UserFile, msg => File.AppendAllText(log, msg + "\r\n"));
                File.AppendAllText(log, "done: " + n + " known security holes\r\n");
                return 0;
            }
            catch (Exception ex)
            {
                File.AppendAllText(log, "failed: " + ex.Message + "\r\n");
                return 1;
            }
        }

        // Date the file was generated (the "G" line), or null if it is missing or unreadable.
        public static DateTime? Generated(string path)
        {
            try
            {
                foreach (string line in File.ReadLines(path))
                    if (line.StartsWith("G\t"))
                    {
                        DateTime d;
                        string v = line.Split('\t')[1];
                        return DateTime.TryParse(v, CultureInfo.InvariantCulture,
                                                 DateTimeStyles.AdjustToUniversal | DateTimeStyles.AssumeUniversal, out d)
                            ? (DateTime?)d : null;
                    }
            }
            catch (Exception) { }
            return null;
        }

        // Downloads everything, then replaces outFile in one step. Any source that still fails
        // after retries fails the whole update, so a half-empty list never replaces a good one.
        public static int Update(string outFile, Action<string> progress)
        {
            ServicePointManager.SecurityProtocol |= SecurityProtocolType.Tls12;
            var js = new JavaScriptSerializer { MaxJsonLength = int.MaxValue };
            var vulns = new List<Vuln>();

            progress("CISA known exploited vulnerabilities");
            var kev = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            object k = js.DeserializeObject(Get("https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"));
            foreach (object v in Arr(Field(k, "vulnerabilities")))
                kev.Add(Str(Field(v, "cveID")) ?? "");
            if (kev.Count < 100)
                throw new Exception("the CISA list looks incomplete");

            foreach (string[] p in OsvProducts)
            {
                progress("OSV.dev: " + p[2]);
                vulns.AddRange(FromOsv(js, p[0], p[1], p[2]));
            }
            foreach (string[] p in NvdProducts)
            {
                progress("NVD: " + p[0]);
                var have = new HashSet<string>(vulns.Where(v => v.Product == p[0]).Select(v => v.Id));
                vulns.AddRange(FromNvd(js, p[0], p[1]).Where(v => !have.Contains(v.Id)));
            }
            foreach (Vuln v in vulns)
                v.Kev = kev.Contains(v.Id) || v.Aliases.Any(kev.Contains);

            progress("WordPress.org version table");
            var status = new SortedDictionary<string, string>(StringComparer.Ordinal);
            var sc = js.DeserializeObject(Get("https://api.wordpress.org/core/stable-check/1.0/")) as Dictionary<string, object>;
            if (sc == null || sc.Count < 100)
                throw new Exception("the WordPress.org version table looks incomplete");
            foreach (var kv in sc)
                status[kv.Key] = Str(kv.Value);

            var eol = new List<string>();
            foreach (string[] p in EolProducts)
            {
                progress("endoflife.date: " + p[1]);
                foreach (object c in Arr(js.DeserializeObject(Get("https://endoflife.date/api/" + p[1] + ".json"))))
                    eol.Add(string.Join("\t", "E", p[0], Clean(Str(Field(c, "cycle")), 40), Date(Field(c, "eol")),
                                        Date(Field(c, "extendedSupport")), Clean(Str(Field(c, "latest")) ?? "-", 40)));
            }

            var sb = new StringBuilder();
            sb.Append("# Exposure Scanner security data. Rebuilt by \"ExposureScanner.exe --update-data\"; do not edit.\n");
            sb.Append("# Sources: WordPress.org stable-check, NIST NVD, OSV.dev, CISA KEV, endoflife.date (see app/VulnData.cs).\n");
            sb.Append("# V product id severity score kev ranges fixed url summary | S wordpress version status | E product cycle eol extended latest\n");
            sb.Append("G\t" + DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ssZ", CultureInfo.InvariantCulture) + "\t" +
                      vulns.Count + "\n");
            foreach (Vuln v in vulns.OrderBy(v => v.Product, StringComparer.Ordinal).ThenBy(v => v.Id, StringComparer.Ordinal))
                sb.Append(string.Join("\t", "V", v.Product, v.Id, v.Severity, v.Score, v.Kev ? "1" : "0",
                                      string.Join(";", v.Groups), v.Fixed.Count > 0 ? string.Join(",", v.Fixed) : "-",
                                      v.Url, v.Summary.Length > 0 ? v.Summary : "-") + "\n");
            foreach (var kv in status)
                sb.Append("S\twordpress\t" + Clean(kv.Key, 40) + "\t" + Clean(kv.Value, 20) + "\n");
            foreach (string line in eol)
                sb.Append(line + "\n");

            string dir = Path.GetDirectoryName(Path.GetFullPath(outFile));
            Directory.CreateDirectory(dir);
            string tmp = outFile + ".new";
            File.WriteAllText(tmp, sb.ToString(), new UTF8Encoding(false));
            if (File.Exists(outFile))
                File.Replace(tmp, outFile, null);
            else
                File.Move(tmp, outFile);
            return vulns.Count;
        }

        // ---------------------------------------------------------------- OSV.dev

        static IEnumerable<Vuln> FromOsv(JavaScriptSerializer js, string product, string eco, string pkg)
        {
            var list = new List<Vuln>();
            string token = null;
            for (int page = 0; page < 50; page++)
            {
                string body = js.Serialize(token == null
                    ? (object)new { package = new { name = pkg, ecosystem = eco } }
                    : new { package = new { name = pkg, ecosystem = eco }, page_token = token });
                object r = js.DeserializeObject(Get("https://api.osv.dev/v1/query", body));
                foreach (object o in Arr(Field(r, "vulns")))
                {
                    if (Field(o, "withdrawn") != null)
                        continue;
                    string osvId = Str(Field(o, "id"));
                    string cve = Arr(Field(o, "aliases")).Select(Str).FirstOrDefault(a => a != null && a.StartsWith("CVE-"));
                    var v = new Vuln
                    {
                        Product = product,
                        Id = cve ?? osvId,
                        Url = "https://osv.dev/vulnerability/" + osvId,
                        Summary = Clean(Str(Field(o, "summary")) ?? FirstLine(Str(Field(o, "details"))), 140),
                    };
                    v.Aliases.AddRange(Arr(Field(o, "aliases")).Concat(Arr(Field(o, "related"))).Select(Str).Where(a => a != null));
                    string sev = Str(Field(Field(o, "database_specific"), "severity"));
                    if (sev != null)
                        v.Severity = sev.Equals("MODERATE", StringComparison.OrdinalIgnoreCase) ? "medium" : sev.ToLowerInvariant();
                    foreach (object a in Arr(Field(o, "affected")))
                    {
                        object p = Field(a, "package");
                        if (!string.Equals(Str(Field(p, "name")), pkg, StringComparison.OrdinalIgnoreCase) ||
                            !string.Equals(Str(Field(p, "ecosystem")), eco, StringComparison.OrdinalIgnoreCase))
                            continue;
                        bool ranged = false;
                        foreach (object rg in Arr(Field(a, "ranges")))
                        {
                            string type = Str(Field(rg, "type"));
                            if (type != "ECOSYSTEM" && type != "SEMVER")
                                continue;
                            ranged = true;
                            string start = null;
                            foreach (object ev in Arr(Field(rg, "events")))
                            {
                                string intro = Str(Field(ev, "introduced")), fix = Str(Field(ev, "fixed"));
                                string last = Str(Field(ev, "last_affected")), limit = Str(Field(ev, "limit"));
                                if (intro != null)
                                    start = intro == "0" ? "" : ">=" + Ver(intro);
                                else if (start != null && (fix ?? limit) != null)
                                {
                                    v.Groups.Add(Join(start, "<" + Ver(fix ?? limit)));
                                    if (fix != null)
                                        v.Fixed.Add(Ver(fix));
                                    start = null;
                                }
                                else if (start != null && last != null)
                                {
                                    v.Groups.Add(Join(start, "<=" + Ver(last)));
                                    start = null;
                                }
                            }
                            if (start != null) // introduced and never fixed
                                v.Groups.Add(start.Length > 0 ? start : ">=0");
                        }
                        if (!ranged)
                            foreach (object ver in Arr(Field(a, "versions")).Take(60))
                                v.Groups.Add("=" + Ver(Str(ver)));
                    }
                    if (v.Groups.Count > 0)
                        list.Add(v);
                }
                token = Str(Field(r, "next_page_token"));
                if (string.IsNullOrEmpty(token))
                    break;
            }
            return list;
        }

        // ---------------------------------------------------------------- NVD

        static IEnumerable<Vuln> FromNvd(JavaScriptSerializer js, string product, string cpe)
        {
            var list = new List<Vuln>();
            int start = 0, total = int.MaxValue;
            while (start < total)
            {
                Thread.Sleep(6500); // NVD allows 5 requests per 30 seconds without an API key
                object r = js.DeserializeObject(Get("https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=" +
                                                    Uri.EscapeDataString(cpe) + "&startIndex=" + start));
                total = Int(Field(r, "totalResults"));
                int got = 0;
                foreach (object item in Arr(Field(r, "vulnerabilities")))
                {
                    got++;
                    object c = Field(item, "cve");
                    if ((Str(Field(c, "vulnStatus")) ?? "").StartsWith("Reject"))
                        continue;
                    var v = new Vuln { Product = product, Id = Str(Field(c, "id")) };
                    v.Url = "https://nvd.nist.gov/vuln/detail/" + v.Id;
                    v.Summary = Clean(Arr(Field(c, "descriptions")).Where(d => Str(Field(d, "lang")) == "en")
                                      .Select(d => Str(Field(d, "value"))).FirstOrDefault(), 140);
                    Score(Field(c, "metrics"), v);
                    foreach (object conf in Arr(Field(c, "configurations")))
                        foreach (object node in Arr(Field(conf, "nodes")))
                            foreach (object m in Arr(Field(node, "cpeMatch")))
                            {
                                string crit = Str(Field(m, "criteria")) ?? "";
                                if (!true.Equals(Field(m, "vulnerable")) || !crit.StartsWith(cpe + ":"))
                                    continue;
                                string[] f = crit.Split(':');
                                string exact = f.Length > 5 ? f[5] : "*", upd = f.Length > 6 ? f[6] : "*";
                                if (exact != "*" && exact != "-")
                                {
                                    v.Groups.Add("=" + Ver(exact) + (upd != "*" && upd != "-" ? "-" + upd : ""));
                                    continue;
                                }
                                var g = new List<string>();
                                string si = Str(Field(m, "versionStartIncluding")), se = Str(Field(m, "versionStartExcluding"));
                                string ei = Str(Field(m, "versionEndIncluding")), ee = Str(Field(m, "versionEndExcluding"));
                                if (si != null) g.Add(">=" + Ver(si));
                                if (se != null) g.Add(">" + Ver(se));
                                if (ei != null) g.Add("<=" + Ver(ei));
                                if (ee != null) { g.Add("<" + Ver(ee)); v.Fixed.Add(Ver(ee)); }
                                if (g.Count > 0) // "every version" entries without bounds are not usable
                                    v.Groups.Add(string.Join(",", g));
                            }
                    if (v.Groups.Count > 0)
                        list.Add(v);
                }
                if (got == 0)
                    break;
                start += got;
            }
            return list;
        }

        static void Score(object metrics, Vuln v)
        {
            foreach (string key in new[] { "cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2" })
            {
                object m = Arr(Field(metrics, key)).FirstOrDefault();
                if (m == null)
                    continue;
                object d = Field(m, "cvssData");
                object score = Field(d, "baseScore");
                string sev = Str(Field(d, "baseSeverity")) ?? Str(Field(m, "baseSeverity"));
                if (score != null)
                    v.Score = Convert.ToDecimal(score, CultureInfo.InvariantCulture).ToString("0.0", CultureInfo.InvariantCulture);
                if (sev != null)
                    v.Severity = sev.ToLowerInvariant();
                return;
            }
        }

        // ---------------------------------------------------------------- helpers

        static string Get(string url, string postJson = null)
        {
            for (int attempt = 0; ; attempt++)
            {
                try
                {
                    var req = (HttpWebRequest)WebRequest.Create(url);
                    req.UserAgent = "ExposureScanner/" + Program.Version + " (+" + Program.RepoUrl + ")";
                    req.Timeout = 60000;
                    req.ReadWriteTimeout = 180000;
                    req.AutomaticDecompression = DecompressionMethods.GZip | DecompressionMethods.Deflate;
                    if (postJson != null)
                    {
                        byte[] b = Encoding.UTF8.GetBytes(postJson);
                        req.Method = "POST";
                        req.ContentType = "application/json";
                        req.ContentLength = b.Length;
                        using (Stream s = req.GetRequestStream())
                            s.Write(b, 0, b.Length);
                    }
                    using (var resp = req.GetResponse())
                    using (var sr = new StreamReader(resp.GetResponseStream(), Encoding.UTF8))
                        return sr.ReadToEnd();
                }
                catch (WebException ex)
                {
                    var hr = ex.Response as HttpWebResponse;
                    if (attempt >= 3 || (hr != null && hr.StatusCode == HttpStatusCode.NotFound))
                        throw new Exception(new Uri(url).GetLeftPart(UriPartial.Path) + ": " + ex.Message);
                    Thread.Sleep(6000 * (attempt + 1));
                }
            }
        }

        static object Field(object o, string key)
        {
            var d = o as Dictionary<string, object>;
            object v;
            return d != null && d.TryGetValue(key, out v) ? v : null;
        }

        static IEnumerable<object> Arr(object o)
        {
            var a = o as object[];
            if (a != null)
                return a;
            var l = o as System.Collections.ArrayList;
            return l != null ? l.Cast<object>() : Enumerable.Empty<object>();
        }

        static string Str(object o)
        {
            return o == null ? null : Convert.ToString(o, CultureInfo.InvariantCulture);
        }

        static int Int(object o)
        {
            try { return o == null ? 0 : Convert.ToInt32(o, CultureInfo.InvariantCulture); }
            catch (Exception) { return 0; }
        }

        // endoflife.date fields are a date, true/false, or missing
        static string Date(object o)
        {
            if (o is bool)
                return (bool)o ? "yes" : "no";
            string s = Str(o);
            return string.IsNullOrEmpty(s) ? "-" : Clean(s, 20);
        }

        static string Ver(string s)
        {
            s = (s ?? "").Trim();
            return Clean(s.StartsWith("v") || s.StartsWith("V") ? s.Substring(1) : s, 40).Replace(",", "").Replace(";", "");
        }

        static string Join(string start, string end)
        {
            return start.Length > 0 ? start + "," + end : end;
        }

        static string FirstLine(string s)
        {
            if (s == null)
                return "";
            int i = s.IndexOf('\n');
            return i >= 0 ? s.Substring(0, i) : s;
        }

        static string Clean(string s, int max)
        {
            if (string.IsNullOrEmpty(s))
                return "";
            var sb = new StringBuilder(s.Length);
            bool space = false;
            foreach (char ch in s)
            {
                if (char.IsWhiteSpace(ch) || char.IsControl(ch))
                {
                    space = sb.Length > 0;
                    continue;
                }
                if (space)
                    sb.Append(' ');
                space = false;
                sb.Append(ch);
            }
            string r = sb.ToString();
            return r.Length > max ? r.Substring(0, max - 3).TrimEnd() + "..." : r;
        }
    }
}
