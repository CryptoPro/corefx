// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests.CertificateCreation
{
    public static class GostCertificateRequestTests
    {
        [Fact]
        public static void TestGost2012_256AsciiCn()
        {
            var cn = $"CN={"Ascii"}";
            using (var provider = GostCertificateRequestTests.GenerateProvider(KeyNumber.Exchange, Constants.Algorithms.Gost3410_2012_256))
            {
                try
                {
                    CertificateRequest certificateRequest = new CertificateRequest(
                            cn,
                            (Gost3410_2012_256)provider,
                            HashAlgorithmName.Gost3411_2012_256);

                    certificateRequest.CertificateExtensions.Add(
                           new X509KeyUsageExtension(
                               X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment,
                               false));

                    var oidCollection = new OidCollection();
                    // Проверка подлинности клиента (1.3.6.1.5.5.7.3.2)
                    oidCollection.Add(new Oid("1.3.6.1.5.5.7.3.2"));

                    certificateRequest.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            oidCollection,
                            true));

                    certificateRequest.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

                    var cert = certificateRequest.CreateSelfSigned(
                            DateTimeOffset.Now.AddDays(-45),
                            (DateTimeOffset.Now.AddDays(45)));

                    Assert.Equal(cert.Subject, cn);
                }
                finally
                {
                   
                }
            }
        }

        [Fact]
        public static void TestGost2012_256UnicodeCn()
        {
            var cn = $"CN={"Unicode_ёёёё"}";
            using (var provider = GostCertificateRequestTests.GenerateProvider(KeyNumber.Exchange, Constants.Algorithms.Gost3410_2012_256))
            {
                try
                {
                    CertificateRequest certificateRequest = new CertificateRequest(
                            cn,
                            (Gost3410_2012_256)provider,
                            HashAlgorithmName.Gost3411_2012_256);

                    certificateRequest.CertificateExtensions.Add(
                           new X509KeyUsageExtension(
                               X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.NonRepudiation | X509KeyUsageFlags.KeyEncipherment,
                               false));

                    var oidCollection = new OidCollection();
                    // Проверка подлинности клиента (1.3.6.1.5.5.7.3.2)
                    oidCollection.Add(new Oid("1.3.6.1.5.5.7.3.2"));

                    certificateRequest.CertificateExtensions.Add(
                        new X509EnhancedKeyUsageExtension(
                            oidCollection,
                            true));

                    certificateRequest.CertificateExtensions.Add(
                        new X509SubjectKeyIdentifierExtension(certificateRequest.PublicKey, false));

                    var cert = certificateRequest.CreateSelfSigned(
                            DateTimeOffset.Now.AddDays(-45),
                            (DateTimeOffset.Now.AddDays(45)));

                    Assert.Equal(cert.Subject, cn);
                }
                finally
                {
                    
                }
            }
        }

        private static AsymmetricAlgorithm GenerateProvider(KeyNumber selectedKeyNumber, string selectedAlgorithm)
        {
            var keyNumber = selectedKeyNumber == KeyNumber.Exchange ? (int)KeyNumber.Exchange : (int)KeyNumber.Signature;

            switch (selectedAlgorithm)
            {
                case Constants.Algorithms.Gost3410_2001:
                {
                    CspParameters cpsParams = new CspParameters(
                        75,
                        "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider",
                        "\\\\.\\HDIMAGE\\G2001256");
                    return new Gost3410CryptoServiceProvider(cpsParams);
                }
                case Constants.Algorithms.Gost3410_2012_256:
                {

                    CspParameters cpsParams = new CspParameters(
                        80,
                        "",
                        "\\\\.\\HDIMAGE\\G2012256");
                    return new Gost3410_2012_256CryptoServiceProvider(cpsParams);
                }
                case Constants.Algorithms.Gost3410_2012_512:
                {
                    CspParameters cpsParams = new CspParameters(
                        81,
                        "",
                        "\\\\.\\HDIMAGE\\G2012512");
                     return new Gost3410_2012_512CryptoServiceProvider(cpsParams);
                }
                case Constants.Algorithms.RSA:
                {
                    return RSA.Create();
                }
                default:
                {
                    throw new ArgumentException();
                }
            }
        }
    }

    public class Constants
    {
        public static class Algorithms
        {
            public const string Gost3410_2012_256 = "GOST R 34.10.2012-256";

            public const string Gost3410_2012_512 = "GOST R 34.10.2012-512";

            public const string Gost3410_2001 = "GOST R 34.10.2001";

            public const string RSA = "RSA";
        }
    }
}
