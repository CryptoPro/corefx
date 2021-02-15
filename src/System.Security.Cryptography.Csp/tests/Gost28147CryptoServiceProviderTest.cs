using System.Linq;
using System.Security.Cryptography.Csp.Tests;
using System.Text;
using Test.Cryptography;
using Xunit;

namespace System.Security.Cryptography.Csp.Tests
{
    public class Gost28147CryptoServiceProviderTest
    {
        private static readonly byte[] WellKnownKey = new byte[]
        {
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
            0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
            0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
            0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
        };

        private static readonly byte[] WellKnownData = new byte[]
        {
            0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
            0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
        };
        private static readonly byte[] WellKnownUnpaddedData = new byte[]
        {
            0x11, 0x22, 0x33
        };

        [Fact]
        public void PaddingStream_PaddedEncrypt()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.CFB;
            key.Padding = PaddingMode.None;

            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            Assert.Equal(WellKnownUnpaddedData.Length, encypted.Length);

            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);

            Assert.Equal(WellKnownUnpaddedData, decrypted);
        }

        [Fact]
        public void PaddingNone_PaddedEncrypt()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.None;

            ICryptoTransform encryptor = key.CreateEncryptor();
            Assert.Equal(8, encryptor.InputBlockSize);
            Assert.Equal(8, encryptor.OutputBlockSize);

            byte[] encypted = encryptor.TransformFinalBlock(WellKnownData,
                0, WellKnownData.Length);
            Assert.Equal(WellKnownData.Length, encypted.Length);

            ICryptoTransform decryptor = key.CreateDecryptor();
            Assert.Equal(8, decryptor.InputBlockSize);
            Assert.Equal(8, decryptor.OutputBlockSize);

            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);
            Assert.Equal(WellKnownData, decrypted);
        }

        [Fact]
        public void PaddingNone_UnpaddedEncrypt()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.None;
            ICryptoTransform encryptor = key.CreateEncryptor();
            Assert.ThrowsAny<CryptographicException>(() => encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length));
        }

        [Fact]
        public void PaddingZero_Unpadded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.Zeros;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted, 0, encypted.Length);
            byte[] expected = new byte[] { 0x11, 0x22, 0x33, 0, 0, 0, 0, 0 };
            Assert.Equal(expected, decrypted);
        }

        [Fact]
        public void PaddingZero_Padded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.Zeros;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownData,
                0, WellKnownData.Length);
            Assert.Equal(WellKnownData.Length, encypted.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);
            Assert.Equal(WellKnownData, decrypted);
        }

        [Fact]
        public void PaddingANSIX923_Unpadded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.ANSIX923;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted, 0, encypted.Length);
            Assert.Equal(WellKnownUnpaddedData, decrypted);
        }

        [Fact]
        public void PaddingANSIX923_Padded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.ANSIX923;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownData,
                0, WellKnownData.Length);
            Assert.Equal(WellKnownData.Length + 8, encypted.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);
            Assert.Equal(WellKnownData, decrypted);
        }

        [Fact]
        public void PaddingANSIX923_PaddedSetValid()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.ANSIX923;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            Assert.Equal(8, encypted.Length);

            // Расшифровываем без padding
            key.Padding = PaddingMode.None;
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);

            // Один в один проверяем что ожидаем.
            byte[] expected = new byte[] {
                0x11, 0x22, 0x33,
                0x00, 0x00, 0x00, 0x00,
                0x05 };
            Assert.Equal(expected, decrypted);
        }

        [Fact]
        public void PaddingANSIX923_PaddedCheckValid()
        {
            byte[] invalidPadding = new byte[] {
                0x11, 0x22, 0x33,
                0x00, 0x00, 0x00,
                0x01, // Ошибка!
                0x05 };

            // Шифруем без padding
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.None;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(invalidPadding,
                0, invalidPadding.Length);
            Assert.Equal(8, encypted.Length);

            // Расшифровываем как бы с padding
            key.Padding = PaddingMode.ANSIX923;
            ICryptoTransform decryptor = key.CreateDecryptor();
            // Не пользуемся ExpectedExceptionAttribute он может случится на encrypt
            Assert.ThrowsAny<CryptographicException>(() => decryptor.TransformFinalBlock(encypted,
                    0, encypted.Length));

        }

        [Fact]
        public void PaddingANSIX923_PaddedCheckValidBlock()
        {
            byte[] invalidPadding = new byte[] {
                0x11, 0x22, 0x33,
                0x00, 0x00, 0x00, 0x00,
                0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                0x0D // Ошибка!
            };

            // Шифруем без padding
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.None;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(invalidPadding,
                0, invalidPadding.Length);
            Assert.Equal(16, encypted.Length);

            // Расшифровываем как бы с padding
            key.Padding = PaddingMode.ANSIX923;
            ICryptoTransform decryptor = key.CreateDecryptor();
            // Не пользуемся ExpectedExceptionAttribute он может случится на encrypt

            Assert.ThrowsAny<CryptographicException>(() => decryptor.TransformFinalBlock(encypted,
                    0, encypted.Length));
        }

        [Fact]
        public void PaddingPKCS7_Unpadded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.PKCS7;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted, 0, encypted.Length);
            Assert.Equal(WellKnownUnpaddedData, decrypted);
        }

        [Fact]
        public void PaddingPKCS7_Padded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.PKCS7;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownData,
                0, WellKnownData.Length);
            Assert.Equal(WellKnownData.Length + 8, encypted.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);
            Assert.Equal<byte>(WellKnownData, decrypted);
        }

        [Fact]
        public void PaddingPKCS7_PaddedSetValid()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.PKCS7;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            Assert.Equal(8, encypted.Length);

            // Расшифровываем без padding
            key.Padding = PaddingMode.None;
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);

            // Один в один проверяем что ожидаем.
            byte[] expected = new byte[] {
                0x11, 0x22, 0x33,
                0x05, 0x05, 0x05, 0x05,
                0x05 };
            Assert.Equal<byte>(expected, decrypted);
        }

        [Fact]
        public void PaddingPKCS7_PaddedCheckValid()
        {
            byte[] invalidPadding = new byte[] {
                0x11, 0x22, 0x33,
                0x05, 0x05, 0x05,
                0x01, // Ошибка!
                0x05 };

            // Шифруем без padding
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.None;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(invalidPadding,
                0, invalidPadding.Length);
            Assert.Equal(8, encypted.Length);

            // Расшифровываем как бы с padding
            key.Padding = PaddingMode.PKCS7;
            ICryptoTransform decryptor = key.CreateDecryptor();
            // Не пользуемся ExpectedExceptionAttribute он может случится на encrypt
            Assert.ThrowsAny<CryptographicException>(() => decryptor.TransformFinalBlock(encypted,
                    0, encypted.Length));
        }

        [Fact]
        public void PaddingPKCS7_PaddedCheckValidBlock()
        {
            byte[] invalidPadding = new byte[] {
                0x11, 0x22, 0x33,
                0x0D, 0x0D, 0x0D, 0x0D,
                0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
                0x0D // Ошибка!
            };

            // Шифруем без padding
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.None;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(invalidPadding,
                0, invalidPadding.Length);
            Assert.Equal(16, encypted.Length);

            // Расшифровываем как бы с padding
            key.Padding = PaddingMode.PKCS7;
            ICryptoTransform decryptor = key.CreateDecryptor();
            // Не пользуемся ExpectedExceptionAttribute он может случится на encrypt
            Assert.ThrowsAny<CryptographicException>(() => decryptor.TransformFinalBlock(encypted,
                    0, encypted.Length));
        }

        [Fact]
        public void PaddingISO10126_Unpadded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.ISO10126;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted, 0, encypted.Length);
            Assert.Equal(WellKnownUnpaddedData, decrypted);
        }

        [Fact]
        public void PaddingISO10126_Padded()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.ISO10126;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownData,
                0, WellKnownData.Length);
            Assert.Equal(WellKnownData.Length + 8, encypted.Length);
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);
            Assert.Equal(WellKnownData, decrypted);
        }

        [Fact]
        public void PaddingISO10126_PaddedSetValid()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.ISO10126;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            Assert.Equal(8, encypted.Length);

            // Расшифровываем без padding
            key.Padding = PaddingMode.None;
            ICryptoTransform decryptor = key.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(encypted,
                0, encypted.Length);

            // проверяем что ожидаем из текста.
            Assert.Equal(WellKnownUnpaddedData, decrypted.Take(WellKnownUnpaddedData.Length));
            // проверяем что ожидаем из длины.
            Assert.Equal(5, decrypted[7]);
        }

        [Fact]
        public void PaddingISO10126_PaddedCheckValidBlock()
        {
            byte[] invalidPadding = new byte[] {
                0x11, 0x22, 0x33,
                0x0D, 0x0D, 0x0D, 0x0D,
                0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D, 0x0D,
                0x0D // Ошибка!
            };

            // Шифруем без padding
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.None;
            ICryptoTransform encryptor = key.CreateEncryptor();
            byte[] encypted = encryptor.TransformFinalBlock(invalidPadding,
                0, invalidPadding.Length);
            Assert.Equal(16, encypted.Length);

            // Расшифровываем как бы с padding
            key.Padding = PaddingMode.ISO10126;
            ICryptoTransform decryptor = key.CreateDecryptor();
            // Не пользуемся ExpectedExceptionAttribute он может случится на encrypt
            Assert.ThrowsAny<CryptographicException>(() => decryptor.TransformFinalBlock(encypted,
                    0, encypted.Length));
        }

        [Fact]
        public void ResetNormal()
        {
            Gost28147CryptoServiceProvider key =
                new Gost28147CryptoServiceProvider();
            key.GenerateKey();
            key.Mode = CipherMode.ECB;
            key.Padding = PaddingMode.ANSIX923;
            ICryptoTransform encryptor = key.CreateEncryptor();
            ICryptoTransform decryptor = key.CreateDecryptor();

            // Первое преобразование.
            byte[] encrypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            byte[] decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
            Assert.Equal(WellKnownUnpaddedData, decrypted);

            // Второе преобразование, на тех же encryptor и decryptor
            encrypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
                0, WellKnownUnpaddedData.Length);
            decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
            Assert.Equal(WellKnownUnpaddedData, decrypted);
        }

        [Fact]
        public void CipherOidTest()
        {
            var szOID_Gost28147_89_CryptoPro_A_ParamSet = "1.2.643.2.2.31.1";
            var szOID_Gost28147_89_TC26_Z_ParamSet = "1.2.643.7.1.2.5.1.1";

            using (var gost = new Gost28147CryptoServiceProvider())
            {
                gost.CipherOid = szOID_Gost28147_89_CryptoPro_A_ParamSet;
                Assert.Equal(gost.CipherOid, szOID_Gost28147_89_CryptoPro_A_ParamSet);

                gost.CipherOid = szOID_Gost28147_89_TC26_Z_ParamSet;
                Assert.Equal(gost.CipherOid, szOID_Gost28147_89_TC26_Z_ParamSet);
            }
        }

        //[Fact]
        //public void ResetOnErrorEncrypt()
        //{
        //    Gost28147CryptoServiceProvider key =
        //        new Gost28147CryptoServiceProvider();
        //    key.GenerateKey();
        //    key.Mode = CipherMode.ECB;
        //    key.Padding = PaddingMode.ANSIX923;
        //    ICryptoTransform encryptor = key.CreateEncryptor();
        //    ICryptoTransform decryptor = key.CreateDecryptor();

        //    // Не законченное первое преобразование.
        //    byte[] encrypted = new byte[WellKnownData.Length];
        //    int len = encryptor.TransformBlock(WellKnownData,
        //        0, WellKnownData.Length, encrypted, 0);

        //    // Reset.
        //    encryptor.Reset();

        //    // Второе преобразование, на том же encryptor.
        //    encrypted = encryptor.TransformFinalBlock(WellKnownUnpaddedData,
        //        0, WellKnownUnpaddedData.Length);

        //    // Расшифровываем для проверки правильности зашифрования.
        //    byte[] decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        //    Assert.AreEqual<byte>(WellKnownUnpaddedData, decrypted,
        //        "2. Unexpected encrypted data.");
        //}

        //[Fact]
        //public void ResetOnErrorDecrypt()
        //{
        //    Gost28147CryptoServiceProvider key =
        //        new Gost28147CryptoServiceProvider();
        //    key.GenerateKey();
        //    key.Mode = CipherMode.ECB;
        //    key.Padding = PaddingMode.ANSIX923;
        //    ICryptoTransform encryptor = key.CreateEncryptor();
        //    ICryptoTransform decryptor = key.CreateDecryptor();

        //    // Зашифровываем данные.
        //    byte[] encrypted = encryptor.TransformFinalBlock(WellKnownData,
        //        0, WellKnownData.Length);

        //    // Расшифровываем часть (первый блок).
        //    byte[] decrypted = new byte[WellKnownData.Length];
        //    int length = decryptor.TransformBlock(encrypted, 0, 8, decrypted, 0);

        //    // Reset.
        //    decryptor.Reset();

        //    // Второе преобразование, на том же decryptor.
        //    decrypted = decryptor.TransformFinalBlock(encrypted, 0, encrypted.Length);
        //    Assert.AreEqual<byte>(WellKnownData, decrypted,
        //        "2. Unexpected encrypted data.");
        //}
    }
}
