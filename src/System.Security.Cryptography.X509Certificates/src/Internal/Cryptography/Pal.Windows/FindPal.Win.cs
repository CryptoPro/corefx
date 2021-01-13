// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Diagnostics;
using System.Numerics;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Internal.Cryptography.Pal.Native;

using static Interop.Crypt32;

namespace Internal.Cryptography.Pal
{
    internal partial class FindPal : IFindPal 
    {
        public unsafe void FindBySubjectName(string subjectName)
        {
            fixed (char* pSubjectName = subjectName)
            {
                FindCore(CertFindType.CERT_FIND_SUBJECT_STR, pSubjectName);
            }
        }

        public unsafe void FindByIssuerName(string issuerName)
        {
            fixed (char* pIssuerName = issuerName)
            {
                FindCore(CertFindType.CERT_FIND_ISSUER_STR, pIssuerName);
            }
        }
    }
}