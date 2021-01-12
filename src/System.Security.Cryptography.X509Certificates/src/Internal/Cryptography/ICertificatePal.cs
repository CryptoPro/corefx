// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace Internal.Cryptography
{
    /// <summary>Provides specific implementation for X509Certificate2.</summary>
    internal interface ICertificatePal : ICertificatePalCore
    {
        int Version { get; }
        bool Archived { get; set; }
        string FriendlyName { get; set; }
        X500DistinguishedName SubjectName { get; }
        X500DistinguishedName IssuerName { get; }
        IEnumerable<X509Extension> Extensions { get; }
        RSA GetRSAPrivateKey();
        DSA GetDSAPrivateKey();
        ECDsa GetECDsaPrivateKey();
        //begin: gost
        Gost3410 GetGost3410PrivateKey();
        Gost3410_2012_256 GetGost3410_2012_256PrivateKey();
        Gost3410_2012_512 GetGost3410_2012_512PrivateKey();
        void SetCspPrivateKey(AsymmetricAlgorithm key);
        //end: gost
        string GetNameInfo(X509NameType nameType, bool forIssuer);
        void AppendPrivateKeyInfo(StringBuilder sb);
        ICertificatePal CopyWithPrivateKey(DSA privateKey);
        ICertificatePal CopyWithPrivateKey(ECDsa privateKey);
        ICertificatePal CopyWithPrivateKey(RSA privateKey);
        //begin: gost
        ICertificatePal CopyWithPrivateKey(Gost3410 privateKey);
        ICertificatePal CopyWithPrivateKey(Gost3410_2012_256 privateKey);
        ICertificatePal CopyWithPrivateKey(Gost3410_2012_512 privateKey);
        //end: gost
    }
}
