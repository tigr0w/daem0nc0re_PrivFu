﻿using System;
using System.Runtime.InteropServices;
using System.Text;

namespace TokenDump.Interop
{
    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_ALLOWED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACCESS_DENIED_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public ACE_OBJECT_TYPE Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACE_HEADER
    {
        public ACE_TYPE AceType;
        public ACE_FLAGS AceFlags;
        public short AceSize;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct ACL
    {
        public ACL_REVISION AclRevision;
        public byte Sbz1;
        public short AclSize;
        public short AceCount;
        public short Sbz2;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct GENERIC_MAPPING
    {
        public ACCESS_MASK GenericRead;
        public ACCESS_MASK GenericWrite;
        public ACCESS_MASK GenericExecute;
        public ACCESS_MASK GenericAll;
    }

    [StructLayout(LayoutKind.Explicit, Size = 8)]
    internal struct LARGE_INTEGER
    {
        [FieldOffset(0)]
        public int Low;
        [FieldOffset(4)]
        public int High;
        [FieldOffset(0)]
        public long QuadPart;

        public LARGE_INTEGER(int _low, int _high)
        {
            QuadPart = 0L;
            Low = _low;
            High = _high;
        }

        public LARGE_INTEGER(long _quad)
        {
            Low = 0;
            High = 0;
            QuadPart = _quad;
        }

        public long ToInt64()
        {
            return ((long)High << 32) | (uint)Low;
        }

        public static LARGE_INTEGER FromInt64(long value)
        {
            return new LARGE_INTEGER
            {
                Low = (int)(value),
                High = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID
    {
        public int LowPart;
        public int HighPart;

        public long ToInt64()
        {
            return ((long)this.HighPart << 32) | (uint)this.LowPart;
        }

        public static LUID FromInt64(long value)
        {
            return new LUID
            {
                LowPart = (int)(value),
                HighPart = (int)((value >> 32))
            };
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct LUID_AND_ATTRIBUTES
    {
        public LUID Luid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_TYPE_INFORMATION
    {
        public UNICODE_STRING TypeName;
        public uint TotalNumberOfObjects;
        public uint TotalNumberOfHandles;
        public uint TotalPagedPoolUsage;
        public uint TotalNonPagedPoolUsage;
        public uint TotalNamePoolUsage;
        public uint TotalHandleTableUsage;
        public uint HighWaterNumberOfObjects;
        public uint HighWaterNumberOfHandles;
        public uint HighWaterPagedPoolUsage;
        public uint HighWaterNonPagedPoolUsage;
        public uint HighWaterNamePoolUsage;
        public uint HighWaterHandleTableUsage;
        public uint InvalidAttributes;
        public GENERIC_MAPPING GenericMapping;
        public uint ValidAccessMask;
        public BOOLEAN SecurityRequired;
        public BOOLEAN MaintainHandleCount;
        public byte TypeIndex; // since WINBLUE
        public byte ReservedByte;
        public uint PoolType;
        public uint DefaultPagedPoolCharge;
        public uint DefaultNonPagedPoolCharge;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct OBJECT_TYPES_INFORMATION
    {
        public uint NumberOfTypes;
        // OBJECT_TYPE_INFORMATION data entries are here.
        // Offset for OBJECT_TYPE_INFORMATION entries is IntPtr.Size
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SID_AND_ATTRIBUTES
    {
        public IntPtr Sid;
        public int Attributes;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_INFORMATION
    {
        public uint NumberOfHandles;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SYSTEM_HANDLE_TABLE_ENTRY_INFO[] Handles;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_HANDLE_TABLE_ENTRY_INFO
    {
        public ushort UniqueProcessId;
        public ushort CreatorBackTraceIndex;
        public byte ObjectTypeIndex;
        public byte HandleAttributes;
        public ushort HandleValue;
        public IntPtr Object;
        public uint GrantedAccess;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_DEFAULT_DACL
    {
        public IntPtr /* PACL */ DefaultDacl;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_ELEVATION
    {
        public int TokenIsElevated;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_LINKED_TOKEN
    {
        public IntPtr LinkedToken;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_GROUPS
    {
        public int GroupCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public SID_AND_ATTRIBUTES[] Groups;

        public TOKEN_GROUPS(int nGroupCount)
        {
            GroupCount = nGroupCount;
            Groups = new SID_AND_ATTRIBUTES[1];
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_ORIGIN
    {
        public LUID OriginatingLogonSession;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_OWNER
    {
        public IntPtr Owner;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIMARY_GROUP
    {
        public IntPtr PrimaryGroup;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PRIVILEGES
    {
        public int PrivilegeCount;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1)]
        public LUID_AND_ATTRIBUTES[] Privileges;

        public TOKEN_PRIVILEGES(int nPrivilegeCount)
        {
            PrivilegeCount = nPrivilegeCount;
            Privileges = new LUID_AND_ATTRIBUTES[1];
        }
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
    internal struct TOKEN_SOURCE
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 8)]
        public byte[] SourceName;
        public LUID SourceIdentifier;

        public TOKEN_SOURCE(string sourceName)
        {
            var soureNameBytes = Encoding.ASCII.GetBytes(sourceName);
            int nSourceNameLength = (soureNameBytes.Length > 8) ? 8 : soureNameBytes.Length;
            SourceName = new byte[8];
            SourceIdentifier = new LUID();

            Buffer.BlockCopy(soureNameBytes, 0, SourceName, 0, nSourceNameLength);
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_STATISTICS
    {
        public LUID TokenId;
        public LUID AuthenticationId;
        public LARGE_INTEGER ExpirationTime;
        public TOKEN_TYPE TokenType;
        public SECURITY_IMPERSONATION_LEVEL ImpersonationLevel;
        public int DynamicCharged;
        public int DynamicAvailable;
        public int GroupCount;
        public int PrivilegeCount;
        public LUID ModifiedId;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_PROCESS_TRUST_LEVEL
    {
        public IntPtr TrustLevelSid;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_USER
    {
        public SID_AND_ATTRIBUTES User;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct TOKEN_MANDATORY_LABEL
    {
        public SID_AND_ATTRIBUTES Label;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ACCESS_FILTER_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_ALARM_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_CALLBACK_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_AUDIT_OBJECT_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public uint Flags;
        public Guid ObjectType;
        public Guid InheritedObjectType;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_MANDATORY_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_PROCESS_TRUST_LABEL_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_RESOURCE_ATTRIBUTE_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct SYSTEM_SCOPED_POLICY_ID_ACE
    {
        public ACE_HEADER Header;
        public ACCESS_MASK Mask;
        public int SidStart;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct UNICODE_STRING : IDisposable
    {
        public ushort Length;
        public ushort MaximumLength;
        private IntPtr buffer;

        public UNICODE_STRING(string s)
        {
            Length = (ushort)(s.Length * 2);
            MaximumLength = (ushort)(Length + 2);
            buffer = Marshal.StringToHGlobalUni(s);
        }

        public void Dispose()
        {
            Marshal.FreeHGlobal(buffer);
            buffer = IntPtr.Zero;
        }

        public void SetBuffer(IntPtr pBuffer)
        {
            buffer = pBuffer;
        }

        public override string ToString()
        {
            return Marshal.PtrToStringUni(buffer);
        }
    }
}