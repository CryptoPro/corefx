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
    public class Gost3410_2012_512CryptoServiceProviderTests
    {
        private const int Gost2012_512ProvType = 81;
        private static readonly byte[] bytesToHash =
            new byte[]
            {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            };

        private static readonly byte[] computedHash =
            new byte[]
            {
                0xE3, 0xBF, 0x2A, 0x44, 0xF3, 0x5C, 0xBD, 0x16,
                0x29, 0xEA, 0xE8, 0xA4, 0x2D, 0x41, 0x95, 0xAA,
                0xC2, 0x92, 0x12, 0x54, 0x6C, 0x61, 0x09, 0x29,
                0x57, 0x77, 0xF1, 0x6E, 0xE0, 0xE7, 0x47, 0xD7,
                
                0x5C, 0x72, 0xC9, 0x1F, 0xB8, 0x7B, 0x74, 0x21,
                0xB8, 0x8D, 0x3B, 0xD1, 0xAD, 0xD7, 0x09, 0xDB,
                0xFB, 0x8A, 0x30, 0x84, 0X6C, 0x2E, 0xE5, 0x23,
                0x9A, 0x5C, 0x3F, 0xC3, 0x57, 0x67, 0x1E, 0x29,
            };

        //private static readonly byte[] ComputedSignature =
        //    new byte[]
        //        {
        //            0x5A, 0x54, 0x9F, 0xC1, 0x19, 0x5F, 0x74, 0x31, 0x40, 0x41, 0x89, 0xAD, 0xAD, 0xD2, 0x86, 0x8B,
        //            0xAD, 0xF1, 0xBE, 0x51, 0x9D, 0x23, 0x8E, 0x9A, 0xD1, 0xE8, 0x84, 0x90, 0x41, 0x39, 0x54, 0xD8,
        //            0x06, 0x24, 0xD7, 0x59, 0x28, 0xCB, 0xD3, 0xB9, 0x3A, 0x15, 0x75, 0x6E, 0x70, 0xA5, 0x77, 0x22,
        //            0x5B, 0x63, 0x23, 0x7F, 0x3C, 0x91, 0x5B, 0xBB, 0xC4, 0x94, 0xBC, 0x21, 0x67, 0xBE, 0x1F, 0x28,
        //            0x54, 0xE8, 0x31, 0x72, 0xFF, 0x2F, 0x2B, 0x8D, 0x19, 0x4D, 0x86, 0x2D, 0x55, 0x22, 0x5A, 0xAE,
        //            0xA6, 0x8E, 0x71, 0x6C, 0xDD, 0x8D, 0x1F, 0x77, 0x24, 0x7E, 0xE8, 0xB8, 0x1A, 0x57, 0x05, 0xD2,
        //            0xC7, 0x7E, 0x35, 0xA2, 0xFD, 0x50, 0x11, 0xF7, 0x02, 0x29, 0x04, 0x48, 0xC4, 0x1B, 0x62, 0xA2,
        //            0x77, 0xC1, 0x80, 0x92, 0xBB, 0x24, 0xD6, 0xFC, 0x5E, 0xBF, 0xD5, 0x62, 0xE6, 0x30, 0xA3, 0x63,
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
                Assert.Equal(Gost2012_512ProvType, containerInfo.ProviderType);
            }
        }

        [Fact]
        public void CreateKeyRoundtripBlob()
        {
            const int KeySize = 1024;
            byte[] blob;

            using (var gost = GetGostProvider())
            {
                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;
                Assert.Equal(Gost2012_512ProvType, containerInfo.ProviderType);
                Assert.Equal(KeySize, gost.KeySize);

                blob = gost.ExportCspBlob(false);
            }

            using (var gost = new Gost3410_2012_512CryptoServiceProvider())
            {
                gost.ImportCspBlob(blob);

                CspKeyContainerInfo containerInfo = gost.CspKeyContainerInfo;

                // The provider information is not persisted in the blob
                Assert.Equal(Gost2012_512ProvType, containerInfo.ProviderType);
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
                byte[] signVal = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_512);
                Assert.ThrowsAny<CryptographicException>(() => gost.VerifyHash(hashVal, signVal));
            }
        }

        [Fact]
        public void SignHashDefaultAlgorithmSuccess()
        {
            byte[] hashVal;
            using (Gost3411_2012_512 gostHash = Gost3411_2012_512.Create())
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
            // using (Gost3411_2012_512 gostHash = Gost3411_2012_512.Create())
            // {
                // hashVal = gostHash.ComputeHash(bytesToHash);
            // }

            // using (var gost = GostCertificate.GetGost3410PrivateKey() as Gost3410_2012_512CryptoServiceProvider)
            // {
                // byte[] signVal = gost.SignData(hashVal);
                // Assert.True(gost.VerifyHash(hashVal, signVal));
            // }
        // }

        [Fact]
        public void SignHashInvalidHashAlgorithmThrows()
        {
            byte[] hashVal;
            using (Gost3411_2012_512 gostHash = Gost3411_2012_512.Create())
            {
                hashVal = gostHash.ComputeHash(bytesToHash);
            }

            using (var gost = GetGostProvider())
            {
                Assert.ThrowsAny<CryptographicException>(() => gost.SignHash(hashVal, HashAlgorithmName.SHA512));
            }
        }

        //[Fact(DisplayName = "Тест метода Create и подписи массива данных")]
        //public void Gost3410CreateAndComputeSignatureOnData()
        //{
        //    var gost = Gost3410.Create() as Gost3410_2012_512CryptoServiceProvider;
        //    gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_512);
        //}
        
        [Fact]
        public void Constructor()
        {
            var gost = new Gost3410_2012_512CryptoServiceProvider();
            Assert.NotNull(gost);
        }

        [Fact]
        public void ComputeSignatureOnData()
        {
            using (var gost = GetGostProvider())
            {
                var signature = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_512);
                Assert.NotNull(signature);
            }
        }
        
        [Fact]
        public void ComputeAndValidateSignatureOnData()
        {
            using (var gost = GetGostProvider())
            {
                var signed = gost.SignData(bytesToHash, HashAlgorithmName.Gost3411_2012_512);
                Assert.NotNull(signed);
                var validationResult = gost.VerifyData(bytesToHash, signed, HashAlgorithmName.Gost3411_2012_512);
                Assert.True(validationResult);
            }
        }

        [Fact]
        public void ComputeSignatureOnHash()
        {
            using (var gost = GetGostProvider())
            {
                var signature = gost.SignHash(computedHash, HashAlgorithmName.Gost3411_2012_512);
                Assert.NotNull(signature);
            }
        }
        
        //[Fact]
        //public void ValidateSignatureOnData()
        //{
        //    using (var gost = GetGostProvider())
        //    {
        //        Assert.True(gost.VerifyData(bytesToHash, ComputedSignature, HashAlgorithmName.Gost3411_2012_512));
        //    }
        //}

        //[Fact]
        //public void ValidateSignatureOnHash()
        //{
        //    using (var gost = GetGostProvider())
        //    {
        //        Assert.True(gost.VerifyHash(computedHash, ComputedSignature, HashAlgorithmName.Gost3411_2012_512));
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

        private static Gost3410_2012_512CryptoServiceProvider GetGostProvider()
        {
            CspParameters cpsParams = new CspParameters(
                81,
                "",
                "\\\\.\\HDIMAGE\\G2012512");
            return new Gost3410_2012_512CryptoServiceProvider(cpsParams);
        }
    }
}
