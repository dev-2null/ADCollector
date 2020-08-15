using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace ADCollector
{
    public class Natives
    {

        [DllImport("NETAPI32.dll", SetLastError = true)]
        internal static extern int NetApiBufferFree(IntPtr Buffer);



        [DllImport("NetApi32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        internal static extern UInt32 DsGetSiteName(
            [MarshalAs(UnmanagedType.LPTStr)]
            string ComputerName,
            out IntPtr SiteNameBuffer);




        //https://www.pinvoke.net/default.aspx/ntdsapi/DsGetDomainControllerInfo.html
        [DllImport("ntdsapi.dll", CharSet = CharSet.Auto)]
        internal static extern uint DsGetDomainControllerInfo(
            IntPtr hDs,
            string DomainName,
            uint InfoLevel,
            out uint InfoCount,
            out IntPtr pInf);




        [DllImport("NTDSAPI.dll", CharSet = CharSet.Auto)]
        internal static extern void DsFreeDomainControllerInfo(
        uint InfoLevel,
        uint cInfo,
        IntPtr pInf);




        //https://www.pinvoke.net/default.aspx/netapi32/DsEnumerateDomainTrusts.html
        [DllImport("Netapi32.dll", CallingConvention = CallingConvention.Winapi, SetLastError = true, CharSet = CharSet.Auto)]
        internal static extern uint DsEnumerateDomainTrusts(
            [MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            uint Flags,
            out IntPtr Domains,
            out uint DomainCount);




        //https://www.pinvoke.net/default.aspx/netapi32/NetSessionEnum.html
        [DllImport("netapi32.dll", SetLastError = true)]
        internal static extern int NetSessionEnum(
            [In, MarshalAs(UnmanagedType.LPWStr)] string ServerName,
            [In, MarshalAs(UnmanagedType.LPWStr)] string UncClientName,
            [In, MarshalAs(UnmanagedType.LPWStr)] string UserName,
            Int32 Level, 
            out IntPtr bufptr, 
            int prefmaxlen, 
            ref Int32 entriesread, 
            ref Int32 totalentries, 
            ref Int32 resume_handle);




        //https://www.pinvoke.net/default.aspx/netapi32/NetLocalGroupGetMembers.html
        [DllImport("NetAPI32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int NetLocalGroupGetMembers(
        [MarshalAs(UnmanagedType.LPWStr)] string servername,
        [MarshalAs(UnmanagedType.LPWStr)] string localgroupname,
            int level,
            out IntPtr bufptr,
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            IntPtr resume_handle);


        [DllImport("ADVAPI32.DLL", SetLastError = true, CharSet = CharSet.Unicode)]
        internal static extern bool LogonUser(
        string lpszUsername,
        string lpszDomain,
        string lpszPassword,
        int dwLogonType,
        int dwLogonProvider,
        out SafeAccessTokenHandle phToken);




        //https://www.pinvoke.net/default.aspx/netapi32/NetWkstaUserEnum.html
        //https://docs.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum
        [DllImport("netapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern int NetWkstaUserEnum(
        [In, MarshalAs(UnmanagedType.LPWStr)] string servername,
            int level,
        // 0: users currently logged on to the workstation
        // 1: current users and the domains accessed by the workstation
            out IntPtr bufptr, // WKSTA_USER_INFO_0/WKSTA_USER_INFO_1
            int prefmaxlen,
            out int entriesread,
            out int totalentries,
            ref int resume_handle);




        //https://www.pinvoke.net/default.aspx/userenv/GetAppliedGPOList.html
        //https://docs.microsoft.com/en-us/windows/win32/api/userenv/nf-userenv-getappliedgpolista
        [DllImport("userenv.dll", SetLastError = true)]
        internal static extern int GetAppliedGPOList(
            int dwFlags,
            string pMachineName,
            IntPtr pSidUser,
            IntPtr pGuidExtension,
            out IntPtr ppGPOList);





        [StructLayout(LayoutKind.Sequential)]
        public struct GUID
        {
            public int a;
            public short b;
            public short c;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
            public byte[] d;
        }




        //https://github.com/dahall/Vanara/blob/82f474e7416b159f25be466cf7f397e0bda0857e/PInvoke/UserEnv/UserEnv.cs#L1452
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct GROUP_POLICY_OBJECT
        {
            /// <summary>
            /// <para>Specifies link options. This member can be one of the following values.</para>
            /// <para>GPO_FLAG_DISABLE</para>
            /// <para>This GPO is disabled.</para>
            /// <para>GPO_FLAG_FORCE</para>
            /// <para>Do not override the policy settings in this GPO with policy settings in a subsequent GPO.</para>
            /// </summary>
            public uint dwOptions;

            /// <summary>Specifies the version number of the GPO.</summary>
            public uint dwVersion;

            /// <summary>Pointer to a string that specifies the path to the directory service portion of the GPO.</summary>
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpDSPath;

            /// <summary>Pointer to a string that specifies the path to the file system portion of the GPO.</summary>
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpFileSysPath;

            /// <summary>Pointer to the display name of the GPO.</summary>
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpDisplayName;

            /// <summary>Pointer to a string that specifies a unique name that identifies the GPO.</summary>
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 50)]
            public string szGPOName;

            /// <summary>
            /// <para>Specifies the link information for the GPO. This member may be one of the following values.</para>
            /// <para>GPLinkUnknown</para>
            /// <para>No link information is available.</para>
            /// <para>GPLinkMachine</para>
            /// <para>The GPO is linked to a computer (local or remote).</para>
            /// <para>GPLinkSite</para>
            /// <para>The GPO is linked to a site.</para>
            /// <para>GPLinkDomain</para>
            /// <para>The GPO is linked to a domain.</para>
            /// <para>GPLinkOrganizationalUnit</para>
            /// <para>The GPO is linked to an organizational unit.</para>
            /// </summary>
            public GPO_LINK GPOLink;

            /// <summary>User-supplied data.</summary>
            public IntPtr lParam;

            /// <summary>Pointer to the next GPO in the list.</summary>
            public IntPtr pNext;

            /// <summary>Pointer to the previous GPO in the list.</summary>
            public IntPtr pPrev;

            /// <summary>
            /// Extensions that have stored data in this GPO. The format is a string of <c>GUID</c> s grouped in brackets. For more
            /// information, see the following Remarks section.
            /// </summary>
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpExtensions;

            /// <summary>User-supplied data.</summary>
            public IntPtr lParam2;

            /// <summary>
            /// Path to the Active Directory site, domain, or organization unit to which this GPO is linked. If the GPO is linked to the
            /// local GPO, this member is "Local".
            /// </summary>
            [MarshalAs(UnmanagedType.LPTStr)]
            public string lpLink;
        }




        public enum GPO_LINK
        {
            /// <summary>No link information is available.</summary>
            GPLinkUnknown = 0,

            /// <summary>The GPO is linked to a computer (local or remote).</summary>
            GPLinkMachine,

            /// <summary>The GPO is linked to a site.</summary>
            GPLinkSite,

            /// <summary>The GPO is linked to a domain.</summary>
            GPLinkDomain,

            /// <summary>The GPO is linked to an organizational unit.</summary>
            GPLinkOrganizationalUnit
        }
        //[StructLayout(LayoutKind.Sequential)]
        //public struct GROUP_POLICY_OBJECT
        //{
        //    public int dwOptions;
        //    public int dwVersion;
        //    public string lpDSPath;
        //    public string lpDisplayName;
        //    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 50)]
        //    public byte[] szGPOName;
        //    public int GPOLink;
        //    public int lParam;
        //    public IntPtr pNext;    // point to a GPO
        //    public IntPtr pPrev;
        //    public string lpExtensions;
        //    public int lParam2;
        //    public string lpLink;
        //}




        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto)]
        public struct DS_DOMAIN_CONTROLLER_INFO_2
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NetbiosName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsHostName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string SiteName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string SiteObjectName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ComputerObjectName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string ServerObjectName;  
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NtdsDsaObjectName;
            [MarshalAs(UnmanagedType.Bool)]
            public bool fIsPdc;
            [MarshalAs(UnmanagedType.Bool)]
            public bool fDsEnabled;
            [MarshalAs(UnmanagedType.Bool)]
            public bool fIsGc;
            public GUID SiteObjectGuid;
            public GUID ComputerObjectGuid;
            public GUID ServerObjectGuid;
            public GUID NtdsDsaObjectGuid;
        }




        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct WKSTA_USER_INFO_1
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string username;
            [MarshalAs(UnmanagedType.LPWStr)] public string logon_domain;
            [MarshalAs(UnmanagedType.LPWStr)] public string os_domains;
            [MarshalAs(UnmanagedType.LPWStr)] public string logon_server;
        }




        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct LOCALGROUP_MEMBERS_INFO_2
        {
            public int sid;
            public int sidusage;
            [MarshalAs(UnmanagedType.LPWStr)]
            public string domainandname;
        }




        //https://www.pinvoke.net/default.aspx/Structures/SESSION_INFO_10.html
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        public struct SESSION_INFO_10
        {
            [MarshalAs(UnmanagedType.LPWStr)] public string cname;
            [MarshalAs(UnmanagedType.LPWStr)] public string username;
            public uint session_time;
            public uint idle_time;
        }





        [StructLayout(LayoutKind.Sequential)]
        public struct DS_DOMAIN_TRUSTS
        {
            [MarshalAs(UnmanagedType.LPTStr)]
            public string NetbiosDomainName;
            [MarshalAs(UnmanagedType.LPTStr)]
            public string DnsDomainName;
            public uint Flags;
            public uint ParentIndex;
            public uint TrustType;
            public uint TrustAttributes;
            public IntPtr DomainSid;
            public Guid DomainGuid;
        }






        [Flags]
        public enum GPO_LIST_FLAG
        {
            /// <summary>The gpo list flag machine</summary>
            GPO_LIST_FLAG_MACHINE = 0x00000001,
            /// <summary>The gpo list flag siteonly</summary>
            GPO_LIST_FLAG_SITEONLY = 0x00000002,
            /// <summary>Ignore WMI filters when filtering GPO's</summary>
            GPO_LIST_FLAG_NO_WMIFILTERS = 0x00000004,
            /// <summary>Ignore security filters</summary>
            GPO_LIST_FLAG_NO_SECURITYFILTERS = 0x00000008
        }




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




        [Flags]
        public enum TrustFlags : uint
        {
            InForest = 0x0001,  // Domain is a member of the forest
            DirectOutBound = 0x0002,  // Domain is directly trusted
            TreeRoot = 0x0004,  // Domain is root of a tree in the forest
            Primary = 0x0008,  // Domain is the primary domain of queried server
            NativeMode = 0x0010,  // Primary domain is running in native mode
            DirectInBound = 0x0020   // Domain is directly trusting
        }



        //[MS-ADTS] 6.1.6.7.9
        [Flags]
        public enum TrustAttributes : uint
        {
            NonTransitive = 0x1,
            UplevelOnly = 0x2,
            FilterSids = 0x4,
            ForestTransitive = 0x8,
            CrossOrganization = 0x10,
            WithinForest = 0x20,
            TreatAsExternal = 0x40,
            TrustUsesRc4 = 0x80,
            TrustUsesAes = 0x100,
            CrossOrganizationNoTGTDelegation = 0x200,
            PIMTrust = 0x400,
            CrossOrganizationEnableTGTDelegation = 0x800
        }




        // ([MS-ADTS] section 6.1.6.7.12) trustDirection
        [Flags]
        public enum TrustDirection
        {
            Disable = 0,
            InBound = 1,
            OutBound = 2,
            BiDirectional = 3
        }




        [Flags]
        public enum TrustType
        {
            TreeRoot = 0,
            ParentChild = 1,
            ShortCut = 2,
            External = 3,
            Forest = 4,
            Kerberos = 5,
            Unknown = 6
        }



        [Flags]
        public enum LDAPTrustType
        {
            WindowsNonAD = 1,
            WindowsAD = 2,
            NonWindowsKerberos = 3 
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



    }
}
