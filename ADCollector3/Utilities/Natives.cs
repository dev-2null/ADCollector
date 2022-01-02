using Microsoft.Win32.SafeHandles;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Enums;

namespace ADCollector3
{
    class Natives
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


    }
}
