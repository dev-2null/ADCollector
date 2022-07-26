using Microsoft.Win32;
using NLog;
using System;
using System.Collections.Generic;
using System.DirectoryServices;
using System.DirectoryServices.Protocols;
using System.Globalization;
using System.Linq;
using System.Net;
using System.Net.Security;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.AccessControl;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using SearchScope = System.DirectoryServices.Protocols.SearchScope;

namespace ADCollector3
{
    public static class Helper
    {
        public static Logger logger { get; set; } = LogManager.GetCurrentClassLogger();
        public static Dictionary<string, string> SIDNameMapping { get; set; } = new Dictionary<string, string>();
        public static List<string> ConvertSecurityDescriptor(DirectoryAttribute attribute)
        {
            List<string> descriptors = new List<string>();

            //Resolve Security Descriptor
            //From The .Net Developer Guide to Directory Services Programming Listing 8.2. Listing the DACL

            for (int i = 0; i < attribute.Count; i++)
            {
                ActiveDirectorySecurity ads = new ActiveDirectorySecurity();

                ads.SetSecurityDescriptorBinaryForm((byte[])attribute[i]);

                var rules = ads.GetAccessRules(true, true, typeof(SecurityIdentifier));

                foreach (ActiveDirectoryAccessRule rule in rules)
                {
                    string name = rule.IdentityReference.ToString();

                    if (name.ToUpper().Contains("S-1-5")) { name = SIDNameSID(name); }

                    descriptors.Add(name + " ([ControlType: " + rule.AccessControlType.ToString() + "] Rights: " + rule.ActiveDirectoryRights.ToString() + ")");
                }
            }

            return descriptors;
        }


        public static List<string> ConvertByteArrayToSID(DirectoryAttribute attribute)
        {
            List<string> descriptors = new List<string>();

            for (int i = 0; i < attribute.Count; i++)
            {
                var sid = new SecurityIdentifier((byte[])attribute[i], 0).ToString();

                var name = SIDNameSID(sid);

                if (name == null)
                {
                    descriptors.Add(sid);
                }
                else
                {
                    descriptors.Add(name);
                }
            }
            return descriptors;
        }


        public static string ConvertByteArrayToSID(byte[] attribute)
        {
            return new SecurityIdentifier(attribute, 0).ToString();
        }


        public static string ConvertAscii(DirectoryAttribute charArray)
        {
            string pwd = string.Empty;
            foreach (char c in charArray)
            {
                pwd += Convert.ToChar((int)c);
            }
            return pwd;
        }

        //https://support.microsoft.com/en-us/kb/243330
        public static string ConvertSIDToName(string sid)
        {
            if (SIDNameMapping.ContainsKey(sid))
            {
                return SIDNameMapping[sid];
            }

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
                    return "Local Service";
                case "S-1-5-20":
                    return "Network Service";
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
                        string dn = Searcher.LdapInfo.DomainSID.Contains(sid) ? Searcher.LdapInfo.RootDN : Searcher.LdapInfo.ForestDN;
                        name = (string)Searcher.GetSingleAttributeValue(dn ,string.Format("(objectSid={0})", sid), "name");
                        if (name == null) { name = sid; }
                    }
                    //Need to check if key exists, Async may get error
                    if (!SIDNameMapping.ContainsKey(sid))
                    {
                        SIDNameMapping.Add(sid, name);
                    }
                    
                    return name;

            }
        }


        //SID <=> Name
        public static string SIDNameSID(string name)
        {
            var sidRx = new Regex("^S-1-.*");

            if (sidRx.IsMatch(name))
            {
                return ConvertSIDToName(name);
            }
            else
            {
                var objectSid = (byte[])Searcher.GetSingleAttributeValue(Searcher.LdapInfo.RootDN,$"(name={name})", "objectsid");

                try
                {
                    return new SecurityIdentifier(objectSid, 0).ToString();
                }
                catch { return name; }
            }
        }


        public static DateTime ConvertWhenCreated(string when)
        {
            string format = "yyyyMMddHHmmss.0Z";
            DateTime whenCreated = DateTime.ParseExact(when, format, CultureInfo.InvariantCulture);
            return whenCreated;
        }


        public static string ConvertLargeInteger(string number, bool useDay)
        {
            if (useDay)
            {
                return (BigInteger.Parse(number.Replace("-", null) + "00") / (60000000000 * 60 * 24)) + " Days";
            }
            else
            {
                return (BigInteger.Parse(number.Replace("-", null) + "00") / 60000000000) + " Minutes";
            }
        }

        //public static string ConvertLargeInteger(Object LI, bool useDay)
        //{
        //    try
        //    {
        //        var ILI = (IAdsLargeInteger)LI;
        //        var lLI = ILI.HighPart * 0x100000000 + ILI.LowPart;
        //        Int32 intLI;
        //        if (useDay)
        //        {
        //            intLI = TimeSpan.FromTicks(lLI).Days * -1;
        //            return intLI + " Days";
        //        }
        //        else
        //        {
        //            intLI = TimeSpan.FromTicks(lLI).Minutes * -1;
        //            return intLI + " Minutes";
        //        }
        //    }
        //    catch { return null; }
        //}


        //[ComImport, Guid("9068270b-0939-11d1-8be1-00c04fd8d503"), InterfaceType(ComInterfaceType.InterfaceIsDual)]
        //internal interface IAdsLargeInteger
        //{
        //    long HighPart
        //    {
        //        [SuppressUnmanagedCodeSecurity]
        //        get; [SuppressUnmanagedCodeSecurity]
        //        set;
        //    }

        //    long LowPart
        //    {
        //        [SuppressUnmanagedCodeSecurity]
        //        get; [SuppressUnmanagedCodeSecurity]
        //        set;
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


        public static string GetStringFromByte(byte[] b)
        {
            return new Guid((byte[])b).ToString(); 
        }


        public static string TestWebConnection(string url)
        {
            var req = (HttpWebRequest)WebRequest.Create(url);
            req.Timeout = 3000;
            var cache = new CredentialCache();
            cache.Add(new Uri(url), "NTLM", CredentialCache.DefaultNetworkCredentials);

            HttpWebResponse response = null;
            ServicePointManager.ServerCertificateValidationCallback = new RemoteCertificateValidationCallback(delegate { return true; });
            try
            {
                response = (HttpWebResponse)req.GetResponse();
                if (response.StatusCode == HttpStatusCode.OK) { return url; } else { return null; }
            }
            catch (WebException e)
            {
                if (e.Status == WebExceptionStatus.ConnectFailure || e.Status == WebExceptionStatus.ConnectionClosed || e.Status == WebExceptionStatus.SendFailure) { return null; }
                var resp = e.Response as HttpWebResponse;
                if (resp == null) { return null; }
                if (resp.StatusCode == HttpStatusCode.Unauthorized) { return url; }
                return null;
            }
        }


        public static RegistryKey ReadRemoteReg(string hostname, RegistryHive regHive, string regLocation)
        {
            RegistryKey baseKey = null;
            try
            {
                baseKey = RegistryKey.OpenRemoteBaseKey(regHive, hostname);
            }
            catch
            {
                logger.Warn($"Cannot connect to remote reg hive on {hostname}");
                return null;
            }

            RegistryKey key = null;
            try
            {
                key = baseKey.OpenSubKey(regLocation);
            }
            catch (SecurityException e)
            {
                logger.Warn($"Cannot open remote reg '{regLocation}' on {hostname} {e.Message}");
                return null;
            }
            return key;
        }


        public static bool IsLowPrivSid(string sid)
        {
            return Regex.IsMatch(sid, @"^S-1-5-21-.+-(513|515|545)$") // Domain Users, Domain Computers, Users
                || sid == "S-1-1-0"   // Everyone
                || sid == "S-1-5-11"; // Authenticated Users
        }


        public static string CheckFile(List<string> xmlList, string file)
        {
            logger.Debug($"Checking {file}");
            try
            {
                if (xmlList.Any(file.Contains))
                {
                    logger.Debug($"{file} Exists");
                    return file;
                }
            }
            catch { }
            return null;
        }
    }
}
