/*
  LICENSE
  -------
  Copyright (C) 2018 Juhachi Konoe

  This source code is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this source code or the software it produces.

  Permission is granted to anyone to use this source code for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this source code must not be misrepresented; you must not
     claim that you wrote the original source code.  If you use this source code
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original source code.
  3. This notice may not be removed or altered from any source distribution.
*/

using System;
using System.Runtime.InteropServices;

namespace DSigner
{
    public class NativeMethods
    {
        internal class WTS
        {
            [DllImport("kernel32.dll")]
            internal static extern uint WTSGetActiveConsoleSessionId();

            [DllImport("wtsapi32.dll", SetLastError = true)]
            internal static extern bool WTSQueryUserToken(UInt32 sessionId, out IntPtr Token);
        }

        internal class WinTrust
        {
            internal static Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 = new Guid(0xaac56b, 0xcd44, 0x11d0, 0x8c, 0xc2, 0x0, 0xc0, 0x4f, 0xc2, 0x95, 0xee);

            [DllImport("wintrust.dll", SetLastError = true, CharSet = CharSet.Unicode)]
            internal static extern WinTrustErrorCode WinVerifyTrust(IntPtr hwnd, [MarshalAs(UnmanagedType.LPStruct)] Guid pgActionID, WinTrustData pWVTData);

            internal enum WinTrustErrorCode : uint
            {
                SUCCESS = 0,
                TRUST_E_NOSIGNATURE = 0x800B0100,
                TRUST_E_BAD_DIGEST = 0x80096010,
                TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
            }

            internal enum WinTrustDataUIChoice : uint
            {
                All = 1,
                None = 2,
                NoBad = 3,
                NoGood = 4
            }

            internal enum WinTrustDataRevocationChecks : uint
            {
                None = 0,
                WholeChain = 1
            }

            internal enum WinTrustDataChoice : uint
            {
                File = 1,
                Catalog = 2,
                Blob = 3,
                Signer = 4,
                Certificate = 5
            }

            internal enum WinTrustDataStateAction : uint
            {
                Ignore = 0,
                Verify = 1,
                Close = 2,
                AutoCache = 3,
                AutoCacheFlush = 4
            }

            internal enum WinTrustDataProvFlags : uint
            {
                UseIe4TrustFlag = 0x00000001,
                NoIe4ChainFlag = 0x00000002,
                NoPolicyUsageFlag = 0x00000004,
                RevocationCheckNone = 0x00000010,
                RevocationCheckEndCert = 0x00000020,
                RevocationCheckChain = 0x00000040,
                RevocationCheckChainExcludeRoot = 0x00000080,
                SaferFlag = 0x00000100,
                HashOnlyFlag = 0x00000200,
                UseDefaultOsverCheck = 0x00000400,
                LifetimeSigningFlag = 0x00000800,
                CacheOnlyUrlRetrieval = 0x00001000,
                DisableMD2andMD4 = 0x00002000
            }

            internal enum WinTrustDataUIContext : uint
            {
                Execute = 0,
                Install = 1
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            internal class WinTrustData : IDisposable
            {
                UInt32 cbStruct = (UInt32)Marshal.SizeOf(typeof(WinTrustData));
                IntPtr pPolicyCallbackData = IntPtr.Zero;
                IntPtr pSIPClientData = IntPtr.Zero;
                uint UIChoice;
                uint RevocationChecks;
                uint UnionChoice;
                IntPtr FileInfoPtr;
                uint StateAction;
                IntPtr StateData = IntPtr.Zero;
                [MarshalAs(UnmanagedType.LPWStr)] string URLReference = null;
                WinTrustDataProvFlags ProvFlags;
                uint UIContext;

                public WinTrustData(
                    WinTrustDataUIChoice uiChoice,
                    WinTrustDataRevocationChecks revocationCheck,
                    WinTrustDataChoice unionChoice,
                    WinTrustDataStateAction stateAction,
                    WinTrustDataProvFlags provFlags,
                    WinTrustDataUIContext uiContext,
                    string fileName)
                {
                    this.UIChoice = (uint)uiChoice;
                    this.RevocationChecks = (uint)revocationCheck;
                    this.UnionChoice = (uint)unionChoice;
                    this.StateAction = (uint)stateAction;
                    this.ProvFlags = provFlags;
                    this.UIContext = (uint)uiContext;

                    ProvFlags |= WinTrustDataProvFlags.DisableMD2andMD4;
                    WINTRUST_FILE_INFO wtfiData = new WINTRUST_FILE_INFO(fileName);
                    FileInfoPtr = Marshal.AllocCoTaskMem(Marshal.SizeOf(typeof(WINTRUST_FILE_INFO)));
                    Marshal.StructureToPtr(wtfiData, FileInfoPtr, false);
                }

                #region IDisposable Support
                private bool disposedValue = false; // To detect redundant calls

                protected virtual void Dispose(bool disposing)
                {
                    if (!disposedValue)
                    {
                        if (disposing)
                        {
                            // TODO: dispose managed state (managed objects).
                        }

                        // TODO: set large fields to null.
                        if (FileInfoPtr != IntPtr.Zero)
                        {
                            Marshal.FreeCoTaskMem(FileInfoPtr);
                            FileInfoPtr = IntPtr.Zero;
                        }

                        disposedValue = true;
                    }
                }

                ~WinTrustData()
                {
                    Marshal.FreeCoTaskMem(FileInfoPtr);
                    // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
                    Dispose(false);
                }

                // This code added to correctly implement the disposable pattern.
                public void Dispose()
                {
                    // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
                    Dispose(true);
                    GC.SuppressFinalize(this);
                }
                #endregion
            }

            [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
            private class WINTRUST_FILE_INFO : IDisposable
            {
                UInt32 cbStruct = (UInt32)Marshal.SizeOf(typeof(WINTRUST_FILE_INFO));
                IntPtr pcwszFilePath;
                IntPtr hFile = IntPtr.Zero;
                IntPtr pgKnownSubject = IntPtr.Zero;

                public WINTRUST_FILE_INFO(string filePath)
                {
                    pcwszFilePath = Marshal.StringToCoTaskMemAuto(filePath);
                }

                #region IDisposable Support
                private bool disposedValue = false; // To detect redundant calls

                protected virtual void Dispose(bool disposing)
                {
                    if (!disposedValue)
                    {
                        if (disposing)
                        {
                            // TODO: dispose managed state (managed objects).                            
                        }

                        // TODO: set large fields to null.
                        if (pcwszFilePath != IntPtr.Zero)
                        {
                            Marshal.FreeCoTaskMem(pcwszFilePath);
                            pcwszFilePath = IntPtr.Zero;
                        }

                        disposedValue = true;
                    }
                }

                ~WINTRUST_FILE_INFO()
                {
                    // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
                    Dispose(false);
                }

                // This code added to correctly implement the disposable pattern.
                public void Dispose()
                {
                    // Do not change this code. Put cleanup code in Dispose(bool disposing) above.
                    Dispose(true);
                    GC.SuppressFinalize(this);
                }
                #endregion
            }
        }

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool ImpersonateLoggedOnUser(IntPtr hToken);

        [DllImport("advapi32.dll", SetLastError = true)]
        internal static extern bool RevertToSelf();

        [DllImport("kernel32.dll", SetLastError = true)]
        internal static extern bool CloseHandle(IntPtr hObject);
    }
}