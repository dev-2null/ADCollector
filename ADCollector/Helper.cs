using System;
using System.DirectoryServices;
using System.Security.Principal;
using System.Text;

namespace ADCollector2
{
    public class Helper
    {
        [Flags]
        public enum Functionality
        {
            DS_BEHAVIOR_WIN2000 = 0,
            DS_BEHAVIOR_WIN2003_WITH_MIXED_DOMAINS = 1,
            DS_BEHAVIOR_WIN2003 = 2,
            DS_BEHAVIOR_WIN2008 = 3,
            DS_BEHAVIOR_WIN2008R2 = 4,
            DS_BEHAVIOR_WIN2012 = 5,
            DS_BEHAVIOR_WIN2012R2 = 6,
            DS_BEHAVIOR_WIN2016 = 7
        }


        //userAccountControl attribute ([MS-ADTS] section 2.2.16) TD flag 
        [Flags]
        public enum UACFlags
        {
            SCRIPT = 0x1,
            ACCOUNT_DISABLE = 0x2,
            HOMEDIR_REQUIRED = 0x8,
            LOCKOUT = 0x10,
            PASSWD_NOTREQD = 0x20,
            PASSWD_CANT_CHANGE = 0x40,
            ENCRYPTED_TEXT_PASSWORD_ALLOWED = 0x80,
            NORMAL_ACCOUNT = 0x200,
            INTERDOMAIN_TRUST_ACCOUNT = 0x800,
            WORKSTATION_TRUST_ACCOUNT = 0x1000,
            SERVER_TRUST_ACCOUNT = 0x2000,
            DONT_EXPIRE_PASSWD = 0x10000,
            SMARTCART_REQUIRED = 0x40000,
            TRUSTED_FOR_DELEGATION = 0x80000,
            NOT_DELEGATED = 0x100000,
            USE_DES_KEY_ONLY = 0x200000,
            DONT_REQUIRE_PREAUTH = 0x400000,
            PASSWORD_EXPIRED = 0x800000,
            TRUSTED_TO_AUTHENTICATE_FOR_DELEGATION = 0x1000000,
            NO_AUTH_DATA_REQUIRED = 0x2000000,
            PARTIAL_SECRETS_ACCOUNT = 0x4000000
        }


        // ([MS-ADTS] section 6.1.6.7.9) trustAttributes
        [Flags]
        public enum TrustAttributes
        {
            NON_TRANSITIVE = 1,
            UPLEVEL_ONLY = 2,
            QUARANTINED_DOMAIN = 4,
            FOREST_TRANSITIVE = 8,
            CROSS_ORGANIZARION = 16,
            WITHIN_FOREST = 32,
            TREAT_AS_EXTERNAL = 64
        }

        // ([MS-ADTS] section 6.1.6.7.12) trustDirection
        [Flags]
        public enum TrustDirection
        {
            DISABLE = 0,
            INBOUND = 1,
            OUTBOUND = 2,
            BIDIRECTIONAL = 3
        }

        //// ([MS-KILE section 2.2.7) 
        //[Flags]
        //public enum EncryptionType
        //{
        //    DES_CBC_CRC = 1,
        //    DES_CBC_MD5 = 2,
        //    RC4_HMAC_MD5 = 4,
        //    AES128_CTS_HMAC_SHA1_96 = 8,
        //    AES256_CTS_HMAC_SHA1_96 = 16
        //}



        public static string SidToName(string sid)
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
                    //https://stackoverflow.com/questions/499053/how-can-i-convert-from-a-sid-to-an-account-name-in-c-sharp
                    string name = new SecurityIdentifier(sid).Translate(typeof(NTAccount)).ToString();
                    return name;
            }
        }





    }
}
