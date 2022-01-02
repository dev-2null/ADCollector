using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Enums;

namespace ADCollector3
{

    public struct LDAPInfo
    {
        public string RootDN { get; set; }
        public string ForestDN { get; set; }
        public string SchemaDN { get; set; }
        public string ConfigDN { get; set; }
        public string DomainName { get; set; }
        public string ForestName { get; set; }
        public string DomainController { get; set; }
        public string TargetSearchBase { get; set; }
        public string DomainSID { get; set; }
    }


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


}
