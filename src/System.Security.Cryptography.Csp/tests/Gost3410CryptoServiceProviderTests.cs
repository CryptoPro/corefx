// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.


namespace System.Security.Cryptography.Encryption.Gost3410.Tests
{

    using System.Linq;

    using Xunit;

    using System.Security.Cryptography;
    
    using System.Security.Cryptography.X509Certificates;

    /// <summary>
    /// Since SHAxCryptoServiceProvider types wraps IncrementalHash from Algorithms assembly, we only test minimally here.
    /// </summary>
    public class Gost3410CryptoServiceProviderTests
    {
        private const string TestCertificateThumbprint = "acdc0b06b3c034c000b1a52b322f5cf1b208b719";

        private const int Gost2001ProvType = 75;

        private static readonly byte[] bytesToHash =
            new byte[]
            {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            };

        private static readonly byte[] computedHash =
            new byte[]
            {
                0x67, 0x3F, 0x02, 0xB6, 0x97, 0xE0, 0xEC, 0xA2,
                0xC3, 0xEA, 0xA6, 0x48, 0xB5, 0x62, 0x9A, 0x27,
                0xC1, 0x5A, 0x79, 0x44, 0xB7, 0xE7, 0x10, 0xED,
                0x8A, 0x4C, 0xF8, 0xCE, 0xA9, 0x09, 0x9E, 0x0F
            };
            
        private static readonly byte[] ComputedSignature =
            new byte[]
                {
                    0x62, 0x6B, 0x5B, 0x74, 0xCF, 0x3D, 0xFA, 0x7C, 0x22, 0xFD, 0x95, 0x0E, 0xC9, 0x7D, 0xBA,
                    0xE2, 0x0C, 0x24, 0xE8, 0xB1, 0xEB, 0xD2, 0xFC, 0x53, 0x01, 0x7E, 0x4D, 0xDD, 0xF1, 0x52,
                    0xA8, 0xB6, 0xCF, 0x22, 0x12, 0x88, 0x6E, 0x70, 0x8D, 0x12, 0x35, 0xFC, 0x87, 0x5D, 0x62,
                    0x0A, 0xDF, 0x20, 0x4D, 0xD7, 0xEE, 0x42, 0x23, 0x16, 0xCD, 0x18, 0x5C, 0xA0, 0x0A, 0x02,
                    0x77, 0x27, 0xBC, 0x19,
                };

        [Fact]
        public void PublicOnlyCertificateKey()
        {
            using (var gost = GetGostProvider())
            {
                // Test cert contains private key, so it is not PublicOnly
                Assert.False(gost.PublicOnly);
            }
        }

        [Fact]
        public void KeyContainerInfoProvType()
        {
            using (var gost = GetGostProvider())
            {
                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;
                Assert.Equal(Gost2001ProvType, containerInfo.ProviderType);
            }
        }

        [Fact]
        public void CreateKeyRoundtripBlob()
        {
            const int KeySize = 512;
            byte[] blob;

            using (var gost = GetGostProvider())
            {
                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;
                Assert.Equal(Gost2001ProvType, containerInfo.ProviderType);
                Assert.Equal(KeySize, gost.KeySize);

                blob = gost.ExportCspBlob(false);
            }

            using (var gost = new Gost3410CryptoServiceProvider())
            {
                gost.ImportCspBlob(blob);

                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;

                // The provider information is not persisted in the blob
                Assert.Equal(Gost2001ProvType, containerInfo.ProviderType);
                Assert.Equal(KeySize, gost.KeySize);
            }
        }

        [Fact]
        public void VerifyHashInvalidHashAlgorithmThrows()
        {
            byte[] hashVal;
            using (SHA1 sha1 = SHA1.Create())
            {
                hashVal = sha1.ComputeHash(bytesToHash);
            }

            using (var gost = GetGostProvider())
            {
                byte[] signVal = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411);
                Assert.ThrowsAny<CryptographicException>(() => gost.VerifyHash(hashVal, signVal));
            }
        }

        [Fact]
        public void SignHashDefaultAlgorithmSuccess()
        {
            byte[] hashVal;
            using (Gost3411 gostHash = Gost3411.Create())
            {
                hashVal = gostHash.ComputeHash(bytesToHash);
            }

            using (var gost = GetGostProvider())
            {
                byte[] signVal = gost.SignHash(hashVal);
                Assert.True(gost.VerifyHash(hashVal, signVal));
            }
        }

        // [Fact]
        // public void VerifyHashDefaultAlgorithmSuccess()
        // {
            // byte[] hashVal;
            // using (Gost3411 gostHash = Gost3411.Create())
            // {
                // hashVal = gostHash.ComputeHash(bytesToHash);
            // }

            // using (var gost = GostCertificate.GetGost3410PrivateKey() as Gost3410CryptoServiceProvider)
            // {
                // byte[] signVal = gost.SignData(hashVal);
                // Assert.True(gost.VerifyHash(hashVal, signVal));
            // }
        // }

        [Fact]
        public void SignHashInvalidHashAlgorithmThrows()
        {
            byte[] hashVal;
            using (Gost3411 gostHash = Gost3411.Create())
            {
                hashVal = gostHash.ComputeHash(bytesToHash);
            }

            using (var gost = GetGostProvider())
            {
                Assert.ThrowsAny<CryptographicException>(() => gost.SignHash(hashVal, HashAlgorithmName.SHA256));
            }
        }

        //[Fact(DisplayName = "Тест метода Create и подписи массива данных")]
        //public void Gost3410CreateAndComputeSignatureOnData()
        //{
        //    var gost = Gost3410.Create() as Gost3410CryptoServiceProvider;
        //    gost.SignData(bytesToHash, HashAlgorithmName.Gost3411);
        //}
        
        [Fact]
        public void Constructor()
        {
            var gost = new Gost3410CryptoServiceProvider();
        }

        [Fact]
        public void ComputeSignatureOnData()
        {
            using (var gost = GetGostProvider())
            {
                gost.SignData(bytesToHash, HashAlgorithmName.Gost3411);
            }
        }
        
        [Fact]
        public void ComputeAndValidateSignatureOnData()
        {
            using (var gost = GetGostProvider())
            {
                var signed = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411);
                var validationResult = gost.VerifyData(bytesToHash, signed, HashAlgorithmName.Gost3411);
                Assert.True(validationResult);
            }
        }

        [Fact]
        public void ComputeSignatureOnHash()
        {
            using (var gost = GetGostProvider())
            {
                gost.SignHash(computedHash, HashAlgorithmName.Gost3411);
            }
        }
        
        [Fact]
        public void ValidateSignatureOnData()
        {
            using (var gost = GetGostProvider())
            {
                Assert.True(gost.VerifyData(bytesToHash, ComputedSignature, HashAlgorithmName.Gost3411));
            }
        }

        [Fact]
        public void ValidateSignatureOnHash()
        {
            using (var gost = GetGostProvider())
            {
                Assert.True(gost.VerifyHash(computedHash, ComputedSignature, HashAlgorithmName.Gost3411));
            }
        }

        [Fact]
        public void ExportParameters()
        {
            using (var gost = GetGostProvider())
            {
                var csp_params = gost.ExportParameters(false);
                Assert.NotNull(csp_params);
                Assert.NotNull(csp_params.PublicKey);
            }
        }

        [Fact]
        public void CipherOidTest()
        {
            var szOID_Gost28147_89_CryptoPro_A_ParamSet = "1.2.643.2.2.31.1";
            var szOID_Gost28147_89_TC26_Z_ParamSet = "1.2.643.7.1.2.5.1.1";

            using (var gost = GetGostProvider())
            {
                gost.CipherOid = szOID_Gost28147_89_CryptoPro_A_ParamSet;
                Assert.Equal(gost.CipherOid, szOID_Gost28147_89_CryptoPro_A_ParamSet);

                gost.CipherOid = szOID_Gost28147_89_TC26_Z_ParamSet;
                Assert.Equal(gost.CipherOid, szOID_Gost28147_89_TC26_Z_ParamSet);
            }
        }

        private static Gost3410CryptoServiceProvider GetGostProvider()
        {
            CspParameters cpsParams = new CspParameters(
                75,
                "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider",
                "\\\\.\\HDIMAGE\\G2001256");
            return new Gost3410CryptoServiceProvider(cpsParams);
        }
    }
}
