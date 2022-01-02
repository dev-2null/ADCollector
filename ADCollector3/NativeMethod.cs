using NLog;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;
using static ADCollector3.Natives;

namespace ADCollector3
{
    public static class NativeMethod
    {
        static Logger logger { get; set; } = LogManager.GetCurrentClassLogger();


        public static DS_DOMAIN_TRUSTS[] GetDsEnumerateDomainTrusts()
        {
            string SourceDomainName = Searcher.LdapInfo.DomainName;

            logger.Debug($"Enumerating Domain Trust for {SourceDomainName}");

            uint domainCount = 0;
            IntPtr BufferPtr = new IntPtr();

            try
            {
                var result = DsEnumerateDomainTrusts(SourceDomainName, 63, out BufferPtr, out domainCount);
                logger.Debug($"{domainCount} Trust Domain(s) Enumerated");

                if ((domainCount > 0) && (result == 0))
                {
                    var BufferOffset = BufferPtr;
                    var trustResults = new DS_DOMAIN_TRUSTS[domainCount];

                    for (int i = 0; i < domainCount; i++)
                    {
                        trustResults[i] = (DS_DOMAIN_TRUSTS)Marshal.PtrToStructure(BufferOffset, typeof(DS_DOMAIN_TRUSTS));

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + (long)Marshal.SizeOf(typeof(DS_DOMAIN_TRUSTS)));
                    }

                    NetApiBufferFree(BufferPtr);
                    return trustResults;
                }
                return null;
            }
            catch (Exception e)
            {
                logger.Error(e.Message);
                return null;
            }
        }


        public static SESSION_INFO_10[] GetNetSessionEnum(string hostname)
        {
            int EntriesRead, TotalEntries, ResumeHandle;

            EntriesRead = TotalEntries = ResumeHandle = 0;

            try
            {
                var result = NetSessionEnum(hostname, null, null, 10, out IntPtr BufferPtr, -1, ref EntriesRead, ref TotalEntries, ref ResumeHandle);

                if (result != 0)
                {
                    return null;
                }
                else
                {
                    var BufferOffset = BufferPtr;

                    var sessResults = new SESSION_INFO_10[EntriesRead];

                    SESSION_INFO_10 sessionInfo10 = new SESSION_INFO_10();

                    for (int i = 0; i < EntriesRead; i++)
                    {
                        sessResults[i] = (SESSION_INFO_10)Marshal.PtrToStructure(BufferOffset, sessionInfo10.GetType());

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + Marshal.SizeOf(sessionInfo10));
                    }

                    NetApiBufferFree(BufferPtr);

                    return sessResults;
                }
            }
            catch (Exception e)
            {
                logger.Error(e.Message);

                return null;
            }

        }





        public static WKSTA_USER_INFO_1[] GetNetWkstaUserEnum(string hostname)
        {
            int EntriesRead, TotalEntries, ResumeHandle;

            EntriesRead = TotalEntries = ResumeHandle = 0;

            try
            {
                var result = NetWkstaUserEnum(hostname, 1, out IntPtr BufferPtr, -1, out EntriesRead, out TotalEntries, ref ResumeHandle);

                if (result != 0)
                {
                    return null;
                }
                else
                {
                    var BufferOffset = BufferPtr;

                    var wkResults = new WKSTA_USER_INFO_1[EntriesRead];

                    WKSTA_USER_INFO_1 userInfo1 = new WKSTA_USER_INFO_1();


                    for (int i = 0; i < EntriesRead; i++)
                    {
                        wkResults[i] = (WKSTA_USER_INFO_1)Marshal.PtrToStructure(BufferOffset, userInfo1.GetType());

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + Marshal.SizeOf(userInfo1));
                    }

                    NetApiBufferFree(BufferPtr);

                    return wkResults;
                }
            }
            catch (Exception e)
            {
                logger.Error(e.Message);
                return null;
            }
        }





        public static LOCALGROUP_MEMBERS_INFO_2[] GetNetLocalGroupGetMembers(string hostname, string localgroup)
        {
            int EntriesRead, TotalEntries;

            IntPtr ResumeHandle = IntPtr.Zero;

            try
            {
                var result = NetLocalGroupGetMembers(hostname, localgroup, 2, out IntPtr BufferPtr, -1, out EntriesRead, out TotalEntries, ResumeHandle);

                if (EntriesRead > 0)
                {
                    var BufferOffset = BufferPtr;

                    var Results = new LOCALGROUP_MEMBERS_INFO_2[EntriesRead];

                    LOCALGROUP_MEMBERS_INFO_2 groupInfo = new LOCALGROUP_MEMBERS_INFO_2();

                    for (int i = 0; i < EntriesRead; i++)
                    {
                        Results[i] = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(BufferOffset, groupInfo.GetType());

                        BufferOffset = (IntPtr)(BufferOffset.ToInt64() + Marshal.SizeOf(groupInfo));
                    }

                    NetApiBufferFree(BufferPtr);

                    return Results;
                }
                else
                {
                    return null;
                }
            }
            catch (Exception e)
            {
                logger.Error(e.Message);
                return null;
            }
        }


    }
}
