// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal partial class Interop
{
    internal partial class Advapi32
    {
        [Flags]
        internal enum CryptContextAddRefFlags : uint
        {
            None = 0x00000000
        }

        [DllImport(Libraries.Advapi32, SetLastError = true, CharSet = CharSet.Ansi, EntryPoint = "CryptContextAddRef")]
        public static extern bool CryptContextAddRef(
            IntPtr hProv,
            byte[] pdwReserved,
            uint dwFlags);

        [DllImport(Libraries.Advapi32, SetLastError = true, CharSet = CharSet.Ansi, EntryPoint = "CryptContextAddRef")]
        public static extern bool CryptContextAddRef(
            SafeProvHandle hProv,
            byte[] pdwReserved,
            uint dwFlags);
    }
}
