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
        internal enum KeySpec : int
        {
            AT_KEYEXCHANGE = 1,
            AT_SIGNATURE = 2,
        }

        [Flags]
        internal enum CryptSignAndVerifyHashFlags : int
        {
            None = 0x00000000,
            CRYPT_NOHASHOID = 0x00000001,
            CRYPT_TYPE2_FORMAT = 0x00000002,  // Not supported
            CRYPT_X931_FORMAT = 0x00000004,  // Not supported
            CP_ECC_PLAIN_SIGNATURE = 0x00000008,
            CP_ECC_PLAIN_SIGNATURE_CNG_REVERSED = 0x00000020,
        }

        [DllImport(Libraries.Advapi32, CharSet = CharSet.Ansi, SetLastError = true, EntryPoint = "CryptSignHashA")]
        public static extern bool CryptSignHash(
            SafeHashHandle hHash,
            KeySpec dwKeySpec,
            string szDescription,
            CryptSignAndVerifyHashFlags dwFlags,
            [Out] byte[] pbSignature,
            [In, Out] ref int pdwSigLen);

        [DllImport(Libraries.Advapi32, CharSet = CharSet.Ansi, SetLastError = true, EntryPoint = "CryptVerifySignatureA")]
        public static extern bool CryptVerifySignature(
            SafeHashHandle hHash,
            byte[] pbSignature,
            int dwSigLen,
            SafeKeyHandle hPubKey,
            string szDescription,
            CryptSignAndVerifyHashFlags dwFlags);
    }
}
