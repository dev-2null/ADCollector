using Microsoft.Win32;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using static ADCollector.Natives;

namespace ADCollector
{
    public class Helper
    {
       
       
        public static void PrintGreen(string output)
        {
            Console.ForegroundColor = ConsoleColor.Green;
            Console.WriteLine(output);
            Console.ResetColor();
        }



        public static void PrintYellow(string output)
        {
            Console.ForegroundColor = ConsoleColor.Yellow;
            Console.WriteLine(output);
            Console.ResetColor();
        }




        public static string ResolveDNSRecord(byte[] dnsByte)
        {
            var rdatatype = dnsByte[2];

            string ip = null;

            if (rdatatype == 1)
            {
                ip = dnsByte[24] + "." + dnsByte[25] + "." + dnsByte[26] + "." + dnsByte[27];
            }
            return ip;
        }




        public static DateTime ConvertWhenCreated(string when)
        {
            string format = "yyyyMMddHHmmss.0Z";
            DateTime whenCreated = DateTime.ParseExact(when, format, System.Globalization.CultureInfo.InvariantCulture);
            return whenCreated;
        }



        public static int ConvertLargeInteger(Object LI, bool useDay)
        {
            try
            {
                var ILI = (IAdsLargeInteger)LI;
                var lLI = ILI.HighPart * 0x100000000 + ILI.LowPart;
                Int32 intLI;
                if (useDay)
                {
                    intLI = TimeSpan.FromTicks(lLI).Days * -1;
                }
                else
                {
                    intLI = TimeSpan.FromTicks(lLI).Minutes * -1;
                }
                return intLI;

            }
            catch (Exception e)
            {
                PrintYellow("[x] ERROR: " + e.Message);
                return 0;
            }
            
        }


        //public static void ConvertSD(byte[] sd)
        //{

        //    //Resolve Security Descriptor
        //    //From The .Net Developer Guide to Directory Services Programming Listing 8.2. Listing the DACL
        //    ActiveDirectorySecurity ads = new ActiveDirectorySecurity();

        //    ads.SetSecurityDescriptorBinaryForm((byte[])entry.Attributes[attr][0]);

        //    var rules = ads.GetAccessRules(true, true, typeof(NTAccount));

        //    foreach (ActiveDirectoryAccessRule rule in rules)
        //    {
        //        Console.WriteLine("    - {0}: {1}",
        //        Console.WriteLine("    - {0}: {1} ([ControlType: {2}] Rights: {3})",
        //            attr.ToUpper(),
        //            System.Text.Encoding.ASCII.GetString((byte[])entry.Attributes[attr][i]));
        //        rule.IdentityReference.ToString(),
        //                    rule.AccessControlType.ToString(),
        //                    rule.ActiveDirectoryRights.ToString());
        //    }


        //}



        public static string BuildFilterOctetString(byte[] bytes)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.Length; i++)
            {
                sb.AppendFormat("\\{0}", bytes[i].ToString("X2"));
            }
            return sb.ToString();
        }





        [ComImport, Guid("9068270b-0939-11d1-8be1-00c04fd8d503"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        internal interface IAdsLargeInteger
        {
            long HighPart
            {
                [SuppressUnmanagedCodeSecurity]
                get; [SuppressUnmanagedCodeSecurity]
                set;
            }

            long LowPart
            {
                [SuppressUnmanagedCodeSecurity]
                get; [SuppressUnmanagedCodeSecurity]
                set;
            }
        }

        //SID <=> Name
        public static string SIDName(string dn, string name)
        {
            var sidRx = new Regex("^S-1-.*");

            if (sidRx.IsMatch(name))
            {
                return ConvertSIDToName(name);
            }
            else
            {
                var nameResult = Collector.GetSingleResultEntry(dn, $"(name={name})", System.DirectoryServices.Protocols.SearchScope.Subtree, new string[] {"objectsid"}, false);
                try {
                    return new SecurityIdentifier((byte[])nameResult.Attributes["objectsid"][0], 0).ToString();
                }
                catch { return null; }
            }


        }


        public static string GetNameFromSID(string sid)
        {
            string sidFilter = string.Format("(objectSid={0})", sid);

            string[] sidAttr = { "cn" };

            var sidResposne = Collector.GetSingleResultEntry(Collector.rootDn, sidFilter, System.DirectoryServices.Protocols.SearchScope.Subtree, sidAttr, false);
            if (sidResposne == null) { return null; }

            string name = sidResposne.Attributes["cn"][0].ToString();//  + "@" + Collector.domainName.ToUpper();

            return name;

        }


        //https://support.microsoft.com/en-us/kb/243330
        public static string ConvertSIDToName(string sid)
        {
            switch (sid)
            {
                case "S-1-0":
                    return "Null Authority";
                case "S-1-0-0":
                    return "Nobody";
                case "S-1-1":
                    return "World Authority";
                case "S-1-1-0":
                    return "Everyone";
                case "S-1-2":
                    return "Local Authority";
                case "S-1-2-0":
                    return "Local";
                case "S-1-2-1":
                    return "Console Logon";
                case "S-1-3":
                    return "Creator Authority";
                case "S-1-3-0":
                    return "Creator Owner";
                case "S-1-3-1":
                    return "Creator Group";
                case "S-1-3-2":
                    return "Creator Owner Server";
                case "S-1-3-3":
                    return "Creator Group Server";
                case "S-1-3-4":
                    return "Owner Rights";
                case "S-1-4":
                    return "Non-unique Authority";
                case "S-1-5":
                    return "NT Authority";
                case "S-1-5-1":
                    return "Dialup";
                case "S-1-5-2":
                    return "Network";
                case "S-1-5-3":
                    return "Batch";
                case "S-1-5-4":
                    return "Interactive";
                case "S-1-5-6":
                    return "Service";
                case "S-1-5-7":
                    return "Anonymous";
                case "S-1-5-8":
                    return "Proxy";
                case "S-1-5-9":
                    return "Enterprise Domain Controllers";
                case "S-1-5-10":
                    return "Principal Self";
                case "S-1-5-11":
                    return "Authenticated Users";
                case "S-1-5-12":
                    return "Restricted Code";
                case "S-1-5-13":
                    return "Terminal Server Users";
                case "S-1-5-14":
                    return "Remote Interactive Logon";
                case "S-1-5-15":
                    return "This Organization";
                case "S-1-5-17":
                    return "This Organization";
                case "S-1-5-18":
                    return "Local System";
                case "S-1-5-19":
                    return "NT Authority";
                case "S-1-5-20":
                    return "NT Authority";
                case "S-1-5-80-0":
                    return "All Services";
                case "S-1-5-32-544":
                    return "BUILTIN\\Administrators";
                case "S-1-5-32-545":
                    return "BUILTIN\\Users";
                case "S-1-5-32-546":
                    return "BUILTIN\\Guests";
                case "S-1-5-32-547":
                    return "BUILTIN\\Power Users";
                case "S-1-5-32-548":
                    return "BUILTIN\\Account Operators";
                case "S-1-5-32-549":
                    return "BUILTIN\\Server Operators";
                case "S-1-5-32-550":
                    return "BUILTIN\\Print Operators";
                case "S-1-5-32-551":
                    return "BUILTIN\\Backup Operators";
                case "S-1-5-32-552":
                    return "BUILTIN\\Replicators";
                case "S-1-5-32-554":
                    return "BUILTIN\\Pre-Windows 2000 Compatible Access";
                case "S-1-5-32-555":
                    return "BUILTIN\\Remote Desktop Users";
                case "S-1-5-32-556":
                    return "BUILTIN\\Network Configuration Operators";
                case "S-1-5-32-557":
                    return "BUILTIN\\Incoming Forest Trust Builders";
                case "S-1-5-32-558":
                    return "BUILTIN\\Performance Monitor Users";
                case "S-1-5-32-559":
                    return "BUILTIN\\Performance Log Users";
                case "S-1-5-32-560":
                    return "BUILTIN\\Windows Authorization Access Group";
                case "S-1-5-32-561":
                    return "BUILTIN\\Terminal Server License Servers";
                case "S-1-5-32-562":
                    return "BUILTIN\\Distributed COM Users";
                case "S-1-5-32-569":
                    return "BUILTIN\\Cryptographic Operators";
                case "S-1-5-32-573":
                    return "BUILTIN\\Event Log Readers";
                case "S-1-5-32-574":
                    return "BUILTIN\\Certificate Service DCOM Access";
                case "S-1-5-32-575":
                    return "BUILTIN\\RDS Remote Access Servers";
                case "S-1-5-32-576":
                    return "BUILTIN\\RDS Endpoint Servers";
                case "S-1-5-32-577":
                    return "BUILTIN\\RDS Management Servers";
                case "S-1-5-32-578":
                    return "BUILTIN\\Hyper-V Administrators";
                case "S-1-5-32-579":
                    return "BUILTIN\\Access Control Assistance Operators";
                case "S-1-5-32-580":
                    return "BUILTIN\\Access Control Assistance Operators";
                default:
                    string name;
                    try
                    {
                        //https://stackoverflow.com/questions/499053/how-can-i-convert-from-a-sid-to-an-account-name-in-c-sharp
                        name = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
                    }
                    catch
                    {
                        name  = GetNameFromSID(sid);
                    }
                    return name;
                    
            }
        }


        //From https://github.com/GhostPack/Certify/blob/2b1530309c0c5eaf41b2505dfd5a68c83403d031/Certify/Lib/DisplayUtil.cs#L316-L328
        public static bool IsAdminSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(498|500|502|512|516|518|519|521)$")
                   || sid == "S-1-5-9"
                   || sid == "S-1-5-32-544";
        }

        public static bool IsLowPrivSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(513|515|545)$") // Domain Users, Domain Computers, Users
                || sid == "S-1-1-0"   // Everyone
                || sid == "S-1-5-11"; // Authenticated Users
        }




        //Adjusted from https://stackoverflow.com/questions/217902/reading-writing-an-ini-file
        public static Dictionary<String, Dictionary<String, String>> ReadInf(String file)
        {
            Dictionary<String, Dictionary<String, String>> infDict = new Dictionary<string, Dictionary<string, string>>();
            try
            {
                if (!File.Exists(file)) { return null; }

                String inf = File.ReadAllText(file);

                inf = Regex.Replace(inf, @"^\s*;.*$", "", RegexOptions.Multiline);

                //^\[(.+?)\](\r\n.*)+
                char[] removeSquare = new char[] { '[', ']' };

                foreach (var section in Regex.Split(inf, @"\r\n\["))
                {

                    var tempSection = section + "\r\n";

                    Dictionary<String, String> lines = new Dictionary<String, String>();

                    var sectionName = (Regex.Match(tempSection, @"(.*?)\]\r\n", RegexOptions.Singleline)).Value.Trim('\r', '\n', '[', ']');

                    foreach (Match m in Regex.Matches(tempSection, @"^\s*(.*?)\s*=(\s(.*?)\s)|(\r\n)$", RegexOptions.Multiline))
                    {
                        String key = m.Groups[1].Value.Trim(' ', '\r', '\n');
                        String value = m.Groups[2].Value.Trim(' ', '\r', '\n');

                        if (!lines.ContainsKey(key) && (!string.IsNullOrEmpty(key))) { lines[key] = value; }
                    }

                    if (!infDict.ContainsKey(sectionName)) { infDict[sectionName] = lines; }

                }

                return infDict;
            }
            catch (Exception e)
            {
                PrintYellow("[x] ERROR: " + e.Message);
                return null;
            }
            
        }


        public static T ParseMyEnum<T>(string v)
        {
            return (T)Enum.Parse(typeof(T), v);
        }

        public static bool TestWebConnection(string url)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = 3000;
            var cache = new CredentialCache();
            cache.Add(new Uri(url), "NTLM", CredentialCache.DefaultNetworkCredentials);

            HttpWebResponse response = null;
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback( delegate { return true; });
            try
            {
                response = (HttpWebResponse)req.GetResponse();
                return response.StatusCode == HttpStatusCode.OK;
            }
            catch (WebException e) {
                if (e.Status == WebExceptionStatus.ConnectFailure || e.Status == WebExceptionStatus.ConnectionClosed || e.Status == WebExceptionStatus.SendFailure ) { return false; }
                var resp = e.Response as HttpWebResponse;
                if (resp == null) { return false; }
                if (resp.StatusCode == HttpStatusCode.Unauthorized) { return true; }
                return false;
            }
        }


        public static RegistryKey ReadRemoteReg(string hostname, RegistryHive regHive, string regLocation)
        {
            RegistryKey baseKey = null;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(regHive, hostname);
            }
            catch (Exception e)
            {
                PrintYellow("[x] Connecting remote reg hive error: " + e.Message);
            }

            RegistryKey key = null;
            try
            {
                key = baseKey.OpenSubKey(regLocation);
            }
            catch (SecurityException e)
            {
                PrintYellow($"[x] Opening remote reg '{regLocation}' error: " + e.Message);
            }
            return key;
        }

        public static bool HasAuthenticationEKU (List<string> oids)
        {
            if (!oids.Any())
            {
                return false;
            }
            foreach(var oid in oids)
            {
                //          SmartcardLogon          ||    ClientAuthentication    || PKINITClientAuthentication
                if (oid == "1.3.6.1.4.1.311.20.2.2" || oid == "1.3.6.1.5.5.7.3.2" || oid == "1.3.6.1.5.2.3.4")
                {
                    return true;
                }
            }
            
            return false;
        }


        public static bool HasDanagerousEKU(List<string> oids)
        {
            //Empty == AnyPurpose
            if (!oids.Any())
            {
                return true;
            }
            foreach (var oid in oids)
            {
                //          AnyPurpose   ||    CertificateRequestAgent
                if (oid == "2.5.29.37.0" || oid == "1.3.6.1.4.1.311.20.2.1")
                {
                    return true;
                }
            }

            return false;
        }

    }


    public struct Trust
    {
        public string SourceDomainName;
        public string TargetDomainName;
        public string NetbiosName;
        //public string DomainSid;
        public bool IsTransitive;
        public TrustDirection TrustDirection;
        public TrustType TrustType;
        public bool FilteringSID;
        

    }


    public struct AppliedGPOs
    {
        public string OUDn;
        public bool IsBlocking;
        public List<GPOAttributes> LinkedGPOs;
    }


    public struct GPOAttributes
    {
        public string GPOName;
        public string GPOID;
        public bool isEnforced;
    }


    public struct GPP
    {
        public string UserName;
        public string NewName;
        public string CPassword;
        public string Changed;
        public string Path;
        public string AccountName;
        public string RunAs;
    }


    public struct ACLs
    {
        public string IdentityReference;
        public string IdentitySID;
        public string ActiveDirectoryRights;
        public string ObjectType;
        public string ObjectDN;
    }


    public struct RestictedGroups
    {
        public string GPOName;
        public string GPOID;
        public string OUDN;
        public Dictionary<string, Dictionary<string, string>> GroupMembership;
    }


    public struct ADCS
    {
        public string CAName;
        public string whenCreated;
        public string dnsHostName;
        public string enrollServers;
        public string owner;
        public PkiCertificateAuthorityFlags flags;
        public bool allowUserSuppliedSAN;
        public List<X509Certificate2> caCertificates;
        public List<ACLs> securityDescriptors;
        public List<string> certTemplates;
        public List<string> enrollmentEndpoints;
    }

    public struct CertificateTemplates
    {
        public string templateCN;
        public string templateDisplayName;
        public List<string> extendedKeyUsage;
        public int raSigature;
        public string owner;
        public bool isPublished;
        public string publishedBy;
        public msPKICertificateNameFlag certNameFlag;
        public msPKIEnrollmentFlag enrollFlag;
        public List<ACLs> securityDescriptors;
    }




}