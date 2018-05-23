// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections.Generic;
using System.Diagnostics;
using System.Security.Cryptography.Asn1;
using System.Security.Cryptography.Pkcs.Asn1;
using System.Security.Cryptography.X509Certificates;
using Internal.Cryptography;

namespace System.Security.Cryptography.Pkcs
{
    internal partial class CmsSignature
    {
        static partial void PrepareRegistrationGost(Dictionary<string, CmsSignature> lookup)
        {
            lookup.Add(Oids.Gost3410, new GostCmsSignature());
        }

        private sealed class GostCmsSignature : CmsSignature
        {
            protected override bool VerifyKeyType(AsymmetricAlgorithm key)
            {
                return (key as Gost3410) != null;
            }

            internal override bool VerifySignature(
#if netcoreapp
                ReadOnlySpan<byte> valueHash,
                ReadOnlyMemory<byte> signature,
#else
                byte[] valueHash,
                byte[] signature,
#endif
                string digestAlgorithmOid,
                HashAlgorithmName digestAlgorithmName,
                ReadOnlyMemory<byte>? signatureParameters,
                X509Certificate2 certificate)
            {
                Gost3410 publicKey = certificate.GetGost3410PublicKey();

                if (publicKey == null)
                {
                    return false;
                }

                return publicKey.VerifyHash(
                    valueHash,
#if netcoreapp
                    signature.Span,
#else
                    signature,
#endif
                    digestAlgorithmName);
            }

            protected override bool Sign(
#if netcoreapp
                ReadOnlySpan<byte> dataHash,
#else
                byte[] dataHash,
#endif
                HashAlgorithmName hashAlgorithmName,
                    X509Certificate2 certificate,
                    AsymmetricAlgorithm key,
                    bool silent,
                    out Oid signatureAlgorithm,
                    out byte[] signatureValue)
            {
                // If there's no private key, fall back to the public key for a "no private key" exception.
                Gost3410 privateKey = key as Gost3410 ??
                    PkcsPal.Instance.GetPrivateKeyForSigning<Gost3410>(certificate, silent) ?? 
                    null; 

                if (privateKey == null)
                {
                    signatureAlgorithm = null;
                    signatureValue = null;
                    return false;
                }

                signatureAlgorithm = new Oid(Oids.Gost3410, Oids.Gost3410);

#if netcoreapp
                byte[] signature = new byte[privateKey.KeySize / 8];

                bool signed = privateKey.TrySignHash(
                    dataHash,
                    signature,
                    hashAlgorithmName,
                    out int bytesWritten);

                if (signed && signature.Length == bytesWritten)
                {
                    signatureValue = signature;
                    return true;
                }
#endif
                signatureValue = privateKey.SignHash(
#if netcoreapp
                    dataHash.ToArray(),
#else
                    dataHash,
#endif
                    hashAlgorithmName);
                return true;
            }
        }
    }
}
