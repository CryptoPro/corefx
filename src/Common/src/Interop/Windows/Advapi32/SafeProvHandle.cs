// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Safehandle representing HCRYPTPROV
    /// </summary>
    internal sealed class SafeProvHandle : SafeHandleZeroOrMinusOneIsInvalid
    {
        private string _containerName;
        private string _providerName;
        private int _type;
        private uint _flags;
        private bool _fPersistKeyInCsp;

        // begin: gost
        /// <summary>
        /// �������� ����������� handle �� IntPtr � ������������
        /// ���������� ���������� ������.
        /// </summary>
        /// <param name="handle">����� � ���� <c>IntPtr</c>.</param>
        /// <param name="addref"><see langword="true"/> ��� AddRef, 
        /// <see langword="false"/> ��� ��������.</param>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal SafeProvHandle(IntPtr handle, bool addref)
            : base(true)
        {
            if (!addref)
            {
                SetHandle(handle);
                return;
            }

            bool ret = Interop.Advapi32.CryptContextAddRef(handle, null, 0);
            int hr = Marshal.GetLastWin32Error();
            if (ret)
                SetHandle(handle);
            if (!ret)
                throw new CryptographicException(hr);

            // ���������� � true, ��� ��� �� �����, ���� ���� ����� ��� ������������ ������ � Dispose
            // ��� ��� �� ���� ����� ������������� ������ ������� ������
            _fPersistKeyInCsp = true;
        }
        // end: gost

        private SafeProvHandle() : base(true)
        {
            SetHandle(IntPtr.Zero);
            _containerName = null;
            _providerName = null;
            _type = 0;
            _flags = 0;
            _fPersistKeyInCsp = true;
        }

        internal string ContainerName
        {
            get
            {
                return _containerName;
            }
            set
            {
                _containerName = value;
            }
        }

        internal string ProviderName
        {
            get
            {
                return _providerName;
            }
            set
            {
                _providerName = value;
            }
        }

        internal int Types
        {
            get
            {
                return _type;
            }
            set
            {
                _type = value;
            }
        }

        internal uint Flags
        {
            get
            {
                return _flags;
            }
            set
            {
                _flags = value;
            }
        }

        internal bool PersistKeyInCsp
        {
            get
            {
                return _fPersistKeyInCsp;
            }
            set
            {
                _fPersistKeyInCsp = value;
            }
        }

        internal static SafeProvHandle InvalidHandle
        {
            get { return SafeHandleCache<SafeProvHandle>.GetInvalidHandle(() => new SafeProvHandle()); }
        }

        protected override void Dispose(bool disposing)
        {
            if (!SafeHandleCache<SafeProvHandle>.IsCachedInvalidHandle(this))
            {
                base.Dispose(disposing);
            }
        }

        protected override bool ReleaseHandle()
        {
            // Make sure not to delete a key that we want to keep in the key container or an ephemeral key
            if (!_fPersistKeyInCsp && 0 == (_flags & (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_VERIFYCONTEXT))
            {
                // Delete the key container. 

                uint flags = (_flags & (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_MACHINE_KEYSET) | (uint)Interop.Advapi32.CryptAcquireContextFlags.CRYPT_DELETEKEYSET;
                SafeProvHandle hIgnoredProv;

#if TargetsWindows
                bool ignoredSuccess = Interop.Advapi32.CryptAcquireContext(out hIgnoredProv, _containerName, _providerName, _type, flags);
#else
                if (_containerName == null)
                {
                    bool ignoredSuccess = Interop.Advapi32.CryptAcquireContext(out hIgnoredProv, _containerName, _providerName, _type, flags);
                }
                else
                {
                    // csp ������ �������� 1251 - �� � ���� �������� �������������
                    // ���� � ��� - ���������� ������������� ���������, ������� ����
                    // � �� ���������� ���������, �� �� ������� ����� ��� ����������� �\� ��
                    Encoding encoding;
                    try
                    {
                        encoding = Encoding.GetEncoding("windows-1251");
                    }
                    catch (ArgumentException)
                    {
                        encoding = Encoding.GetEncoding(28591); // Latin1
                    }
                    byte[] containerNameBytes = encoding.GetBytes(_containerName);
                    bool ignoredSuccess = Interop.Advapi32.CryptAcquireContextB(out hIgnoredProv, containerNameBytes, _providerName, _type, flags);
                }
#endif
                hIgnoredProv.Dispose();
                // Ignoring success result code as CryptAcquireContext is being called to delete a key container rather than acquire a context.
                // If it fails, we can't do anything about it anyway as we're in a dispose method.
            }

            bool successfullyFreed = Interop.Advapi32.CryptReleaseContext(handle, 0);
            Debug.Assert(successfullyFreed);

            SetHandle(IntPtr.Zero);
            return successfullyFreed;
        }
    }
}
