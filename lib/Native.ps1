#Requires -Version 5.1
<#
    P/Invoke wrappers for read-only Windows network APIs:
      - NetLocalGroupGetMembers (level 2)  -> list local group members (SAMR, read)
      - NetShareEnum (level 1)             -> list share names/types (SRVSVC, read)
      - LookupAccountSid                   -> resolve the localized name of BUILTIN\Administrators
    No API here creates, changes or deletes anything on the target.
#>

if (-not ('ADAudit.Native' -as [type])) {
    Add-Type -TypeDefinition @'
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Security.Principal;
using System.Text;

namespace ADAudit
{
    public class LocalGroupMember
    {
        public string Name;
        public string Sid;
        public int SidUsage;
    }

    public class ShareInfo
    {
        public string Name;
        public uint Type;
        public string Remark;
    }

    public static class Native
    {
        const int MAX_PREFERRED_LENGTH = -1;

        [StructLayout(LayoutKind.Sequential)]
        struct LOCALGROUP_MEMBERS_INFO_2
        {
            public IntPtr lgrmi2_sid;
            public int lgrmi2_sidusage;
            public IntPtr lgrmi2_domainandname;
        }

        [StructLayout(LayoutKind.Sequential)]
        struct SHARE_INFO_1
        {
            public IntPtr shi1_netname;
            public uint shi1_type;
            public IntPtr shi1_remark;
        }

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetLocalGroupGetMembers(string servername, string localgroupname, int level,
            out IntPtr bufptr, int prefmaxlen, out int entriesread, out int totalentries, ref IntPtr resumehandle);

        [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
        static extern int NetShareEnum(string servername, int level, out IntPtr bufptr, int prefmaxlen,
            out int entriesread, out int totalentries, ref int resume_handle);

        [DllImport("netapi32.dll")]
        static extern int NetApiBufferFree(IntPtr buffer);

        [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        static extern bool LookupAccountSid(string lpSystemName, byte[] Sid, StringBuilder lpName, ref int cchName,
            StringBuilder ReferencedDomainName, ref int cchReferencedDomainName, out int peUse);

        public static string LookupLocalName(string server, string sddlSid, out int error)
        {
            SecurityIdentifier sid = new SecurityIdentifier(sddlSid);
            byte[] bin = new byte[sid.BinaryLength];
            sid.GetBinaryForm(bin, 0);
            StringBuilder name = new StringBuilder(256);
            StringBuilder dom = new StringBuilder(256);
            int cn = 256, cd = 256, use;
            if (!LookupAccountSid(server, bin, name, ref cn, dom, ref cd, out use))
            {
                error = Marshal.GetLastWin32Error();
                return null;
            }
            error = 0;
            return name.ToString();
        }

        public static LocalGroupMember[] GetLocalGroupMembers(string server, string group, out int error)
        {
            IntPtr buf;
            int read, total;
            IntPtr resume = IntPtr.Zero;
            List<LocalGroupMember> list = new List<LocalGroupMember>();
            error = NetLocalGroupGetMembers(server, group, 2, out buf, MAX_PREFERRED_LENGTH, out read, out total, ref resume);
            try
            {
                if (error != 0) return list.ToArray();
                int size = Marshal.SizeOf(typeof(LOCALGROUP_MEMBERS_INFO_2));
                for (int i = 0; i < read; i++)
                {
                    LOCALGROUP_MEMBERS_INFO_2 e = (LOCALGROUP_MEMBERS_INFO_2)Marshal.PtrToStructure(
                        new IntPtr(buf.ToInt64() + (long)i * size), typeof(LOCALGROUP_MEMBERS_INFO_2));
                    string sidStr = null;
                    try { if (e.lgrmi2_sid != IntPtr.Zero) sidStr = new SecurityIdentifier(e.lgrmi2_sid).Value; } catch { }
                    LocalGroupMember m = new LocalGroupMember();
                    m.Name = e.lgrmi2_domainandname == IntPtr.Zero ? null : Marshal.PtrToStringUni(e.lgrmi2_domainandname);
                    m.Sid = sidStr;
                    m.SidUsage = e.lgrmi2_sidusage;
                    list.Add(m);
                }
            }
            finally
            {
                if (buf != IntPtr.Zero) NetApiBufferFree(buf);
            }
            return list.ToArray();
        }

        public static ShareInfo[] GetShares(string server, out int error)
        {
            IntPtr buf;
            int read, total;
            int resume = 0;
            List<ShareInfo> list = new List<ShareInfo>();
            error = NetShareEnum(server, 1, out buf, MAX_PREFERRED_LENGTH, out read, out total, ref resume);
            try
            {
                if (error != 0) return list.ToArray();
                int size = Marshal.SizeOf(typeof(SHARE_INFO_1));
                for (int i = 0; i < read; i++)
                {
                    SHARE_INFO_1 s = (SHARE_INFO_1)Marshal.PtrToStructure(
                        new IntPtr(buf.ToInt64() + (long)i * size), typeof(SHARE_INFO_1));
                    ShareInfo si = new ShareInfo();
                    si.Name = s.shi1_netname == IntPtr.Zero ? null : Marshal.PtrToStringUni(s.shi1_netname);
                    si.Type = s.shi1_type;
                    si.Remark = s.shi1_remark == IntPtr.Zero ? null : Marshal.PtrToStringUni(s.shi1_remark);
                    list.Add(si);
                }
            }
            finally
            {
                if (buf != IntPtr.Zero) NetApiBufferFree(buf);
            }
            return list.ToArray();
        }
    }
}
'@
}
