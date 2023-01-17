// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Microsoft.Win32.SafeHandles;
using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;

internal partial class Interop
{
    internal partial class Advapi32
    {
        internal enum CertEncodingType : int
        {
            PKCS_7_ASN_ENCODING = 0x10000,
            X509_ASN_ENCODING = 0x00001,

            All = PKCS_7_ASN_ENCODING | X509_ASN_ENCODING,
        }

        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct CRYPT_BIT_BLOB
        {
            public int cbData;
            public byte* pbData;
            public int cUnusedBits;

            public byte[] ToByteArray()
            {
                if (cbData == 0)
                {
                    return Array.Empty<byte>();
                }

                byte[] array = new byte[cbData];
                Marshal.Copy((IntPtr)pbData, array, 0, cbData);
                return array;
            }
        }

        // CRYPTOAPI_BLOB has many typedef aliases in the C++ world (CERT_BLOB, DATA_BLOB, etc.) We'll just stick to one name here.
        [StructLayout(LayoutKind.Sequential)]
        internal unsafe struct CRYPTOAPI_BLOB
        {
            public CRYPTOAPI_BLOB(int cbData, byte* pbData)
            {
                this.cbData = cbData;
                this.pbData = pbData;
            }

            public int cbData;
            public byte* pbData;

            public byte[] ToByteArray()
            {
                if (cbData == 0)
                {
                    return Array.Empty<byte>();
                }

                byte[] array = new byte[cbData];
                Marshal.Copy((IntPtr)pbData, array, 0, cbData);
                return array;
            }
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CRYPT_ALGORITHM_IDENTIFIER
        {
            public IntPtr pszObjId;
            public CRYPTOAPI_BLOB Parameters;
        }

        [StructLayout(LayoutKind.Sequential)]
        internal struct CERT_PUBLIC_KEY_INFO
        {
            public CRYPT_ALGORITHM_IDENTIFIER Algorithm;
            public CRYPT_BIT_BLOB PublicKey;
        }

        [DllImport(Libraries.Crypt32, CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern bool CryptImportPublicKeyInfo(
            SafeProvHandle hCryptProv,
            CertEncodingType dwCertEncodingType,
            byte[] pInfo,
            out SafeKeyHandle phKey);
    }
}
