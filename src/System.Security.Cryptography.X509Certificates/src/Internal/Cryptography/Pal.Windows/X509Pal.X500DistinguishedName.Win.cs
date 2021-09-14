// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;

using Internal.Cryptography.Pal.Native;

using System.Security.Cryptography.X509Certificates;

namespace Internal.Cryptography.Pal
{
    /// <summary>
    /// A singleton class that encapsulates the native implementation of various X509 services. (Implementing this as a singleton makes it
    /// easier to split the class into abstract and implementation classes if desired.)
    /// </summary>
    internal sealed partial class X509Pal : IX509Pal
    {
        public byte[] X500DistinguishedNameEncode(string distinguishedName, X500DistinguishedNameFlags flag)
        {
            Debug.Assert(distinguishedName != null);

            CertNameStrTypeAndFlags dwStrType = CertNameStrTypeAndFlags.CERT_X500_NAME_STR | MapNameToStrFlag(flag);

            int cbEncoded = 0;
            if (!Interop.crypt32.CertStrToName(CertEncodingType.All, distinguishedName, dwStrType, IntPtr.Zero, null, ref cbEncoded, IntPtr.Zero))
                throw Interop.CPError.GetLastWin32Error().ToCryptographicException();

            byte[] encodedName = new byte[cbEncoded];
            if (!Interop.crypt32.CertStrToName(CertEncodingType.All, distinguishedName, dwStrType, IntPtr.Zero, encodedName, ref cbEncoded, IntPtr.Zero))
                throw Interop.CPError.GetLastWin32Error().ToCryptographicException();

            return encodedName;
        }
    }
}

