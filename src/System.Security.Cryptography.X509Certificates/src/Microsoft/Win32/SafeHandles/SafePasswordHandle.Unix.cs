// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;

namespace Microsoft.Win32.SafeHandles
{
    internal partial class SafePasswordHandle
    {
        const int size_of_wchar_t = 4;
        int curr_len = 0;
        private IntPtr CreateHandle(string password)
        {
            return StringToHGlobalUTF32(password);
            // return StringToHGlobalAnsi(password);
        }

        private IntPtr CreateHandle(SecureString password)
        {
            if (password is null)
            {
                throw new ArgumentNullException(nameof(password));
            }
            IntPtr dest = Marshal.AllocHGlobal((password.Length + 1)* size_of_wchar_t);
            IntPtr src = Marshal.SecureStringToGlobalAllocUnicode(password);
            // We don't want to copy SecureString to managed memory so 
            // manualy convert windows 2 byte wchar to unix 4 byte wchar
            unsafe
                {
                    byte* s = (byte*)src;
                    byte* d = (byte*)dest;
                    for (int i = 0; i < password.Length; i++)
                    {
                        d[4*i] = s[2*i];
                        d[4 * i + 1] = s[2 * i + 1];
                        d[4 * i + 2] = 0;
                        d[4 * i + 3] = 0;
                    }
                    //Final zero
                    d[4 * password.Length] = 0;
                    d[4 * password.Length + 1] = 0;
                    d[4 * password.Length + 2] = 0;
                    d[4 * password.Length + 3] = 0;
                }
            Marshal.FreeHGlobal(src);
            curr_len = password.Length * size_of_wchar_t;
            return dest;
            // return Marshal.SecureStringToGlobalAllocAnsi(password);
        }

        private void FreeHandle()
        {
            //Manualy zerro buffer with secure data
            unsafe
            {
                byte* b = (byte*)handle;
                for (int i = 0; i < curr_len; i++){
                    b[i] = 0;
                }
            }
            Marshal.FreeHGlobal(handle);
            // Marshal.ZeroFreeGlobalAllocAnsi(handle);
        }

        //Copy from Masrshal package with modification to support UTF32
        private unsafe IntPtr StringToHGlobalUTF32(string s)
        {
            if (s is null)
            {
                return IntPtr.Zero;
            }

            long lnb = (s.Length + 1) * (long)size_of_wchar_t;
            int nb = (int)lnb;

            // Overflow checking
            if (nb != lnb)
            {
                throw new ArgumentOutOfRangeException(nameof(s));
            }

            IntPtr hglobal = Marshal.AllocHGlobal((IntPtr)nb);

            StringToUTF32String(s, (byte*)hglobal, nb);
            curr_len = nb;
            return hglobal;
        }

        private static unsafe int StringToUTF32String(string s, byte* buffer, int bufferLength, bool bestFit = false, bool throwOnUnmappableChar = false)
        {
            int convertedBytes;
            fixed (char* pChar = s)
            {
                convertedBytes = Encoding.UTF32.GetBytes(pChar, s.Length, buffer, bufferLength);
            }

            buffer[convertedBytes] = 0;
            buffer[convertedBytes + 1] = 0;
            buffer[convertedBytes + 2] = 0;
            buffer[convertedBytes + 3] = 0;
            return convertedBytes;
        }
    }
}
