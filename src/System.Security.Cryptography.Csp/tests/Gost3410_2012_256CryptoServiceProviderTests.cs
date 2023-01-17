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
    public class Gost3410_2012_256CryptoServiceProviderTests
    {
        private const int Gost2012_256ProvType = 80;
        private static readonly byte[] bytesToHash =
            new byte[]
            {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            };

        private static readonly byte[] computedHash =
            new byte[]
            {
                0xF9, 0xA9, 0x62, 0xCA, 0xFF, 0x60, 0x9E, 0x10,
                0x12, 0x5C, 0x2B, 0xD6, 0xA8, 0x14, 0x09, 0xB6,
                0x57, 0x03, 0x1A, 0xDA, 0xCF, 0xDE, 0xD9, 0x4D,
                0x24, 0x32, 0xC1, 0xA8, 0xD7, 0xD0, 0x8F, 0xA8
            };

        //private static readonly byte[] ComputedSignature =
        //    new byte[]
        //        {
        //            0x11, 0x95, 0x7C, 0x66, 0x71, 0x00, 0x3E, 0xFD, 0x48, 0xC0, 0xD4, 0x5B, 0x1F, 0x03, 0x50,
        //            0xF9, 0x5A, 0x6C, 0xA5, 0x1C, 0xF9, 0x8D, 0x6C, 0x43, 0x2C, 0xFA, 0x98, 0x86, 0x32, 0xE5,
        //            0x8C, 0x15, 0x12, 0x17, 0xE4, 0xEE, 0xE3, 0x83, 0x97, 0x3B, 0x48, 0x3A, 0x7F, 0xC4, 0x09,
        //            0x1C, 0x74, 0x55, 0x10, 0x15, 0x4D, 0x02, 0x63, 0x7D, 0xF3, 0x12, 0xC8, 0x19, 0x4A, 0xA3,
        //            0xFF, 0x8B, 0x71, 0xDC,
        //        };

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
                Assert.Equal(Gost2012_256ProvType, containerInfo.ProviderType);
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
                Assert.Equal(Gost2012_256ProvType, containerInfo.ProviderType);
                Assert.Equal(KeySize, gost.KeySize);

                blob = gost.ExportCspBlob(false);
            }

            using (var gost = new Gost3410_2012_256CryptoServiceProvider())
            {
                gost.ImportCspBlob(blob);

                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;

                // The provider information is not persisted in the blob
                Assert.Equal(Gost2012_256ProvType, containerInfo.ProviderType);
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
                byte[] signVal = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_256);
                Assert.ThrowsAny<CryptographicException>(() => gost.VerifyHash(hashVal, signVal));
            }
        }

        [Fact]
        public void SignHashDefaultAlgorithmSuccess()
        {
            byte[] hashVal;
            using (Gost3411_2012_256 gostHash = Gost3411_2012_256.Create())
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
        // using (Gost3411_2012_256 gostHash = Gost3411_2012_256.Create())
        // {
        // hashVal = gostHash.ComputeHash(bytesToHash);
        // }

        // using (var gost = GostCertificate.GetGost3410PrivateKey() as Gost3410_2012_256CryptoServiceProvider)
        // {
        // byte[] signVal = gost.SignData(hashVal);
        // Assert.True(gost.VerifyHash(hashVal, signVal));
        // }
        // }

        [Fact]
        public void SignHashInvalidHashAlgorithmThrows()
        {
            byte[] hashVal;
            using (Gost3411_2012_256 gostHash = Gost3411_2012_256.Create())
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
        //    var gost = Gost3410.Create() as Gost3410_2012_256CryptoServiceProvider;
        //    gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_256);
        //}

        [Fact]
        public void Constructor()
        {
            var gost = new Gost3410_2012_256CryptoServiceProvider();
            Assert.NotNull(gost);
        }

        [Fact]
        public void ComputeSignatureOnData()
        {
            using (var gost = GetGostProvider())
            {
                var signature = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_256);
                Assert.NotNull(signature);
            }
        }

        [Fact]
        public void ComputeAndValidateSignatureOnData()
        {
            using (var gost = GetGostProvider())
            {
                var signed = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_256);
                Assert.NotNull(signed);
                var validationResult = gost.VerifyData(bytesToHash, signed, HashAlgorithmName.Gost3411_2012_256);
                Assert.True(validationResult);
            }
        }

        [Fact]
        public void ComputeSignatureOnHash()
        {
            using (var gost = GetGostProvider())
            {
                var signature = gost.SignHash(computedHash, HashAlgorithmName.Gost3411_2012_256);
                Assert.NotNull(signature);
            }
        }

        //[Fact]
        //public void ValidateSignatureOnData()
        //{
        //    using (var gost = GetGostProvider())
        //    {
        //        Assert.True(gost.VerifyData(bytesToHash, ComputedSignature, HashAlgorithmName.Gost3411_2012_256));
        //    }
        //}

        //[Fact]
        //public void ValidateSignatureOnHash()
        //{
        //    using (var gost = GetGostProvider())
        //    {
        //        Assert.True(gost.VerifyHash(computedHash, ComputedSignature, HashAlgorithmName.Gost3411_2012_256));
        //    }
        //}

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

        [Fact]
        public void NotAfterTest()
        {
            using (var gost = GetGostProvider())
            {
                var notAfter = gost.NotAfter;
                Assert.True(notAfter < DateTimeOffset.MaxValue);
                Assert.True(notAfter > DateTimeOffset.MinValue);
            }
        }

        private static Gost3410_2012_256CryptoServiceProvider GetGostProvider()
        {
            CspParameters cpsParams = new CspParameters(
                80,
                "",
                "\\\\.\\HDIMAGE\\G2012256");
            return new Gost3410_2012_256CryptoServiceProvider(cpsParams);
        }
    }
}
