using System.Security.Cryptography.X509Certificates;
using Xunit;

namespace System.Security.Cryptography.Pkcs.Tests
{
    public class CspRsaStoreCmsTests
    {
        internal static readonly byte[] bytesToHash =
            new byte[]
            {
                0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
                0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
            };

        [Fact]
        public static void CreateDetachedSignedCmsWithStoreRsa()
        {
            byte[] signature;
            using (var rsaCert = GetRsaCertificate())
            {
                var contentInfo = new ContentInfo(bytesToHash);
                var signedCms = new SignedCms(contentInfo, true);
                CmsSigner cmsSigner = new CmsSigner(rsaCert);
                cmsSigner.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.Now));
                signedCms.ComputeSignature(cmsSigner);
                signature = signedCms.Encode();
                Console.WriteLine($"CMS Sign: {Convert.ToBase64String(signature)}");
            }

            // Создаем объект ContentInfo по сообщению.
            // Это необходимо для создания объекта SignedCms.
            ContentInfo contentInfoVerify = new ContentInfo(bytesToHash);

            // Создаем SignedCms для декодирования и проверки.
            SignedCms signedCmsVerify = new SignedCms(contentInfoVerify, true);

            // Декодируем подпись
            signedCmsVerify.Decode(signature);

            // Проверяем подпись
            signedCmsVerify.CheckSignature(true);
        }

        [Fact]
        public static void CreateAttachedSignedCmsWithStoreRsa()
        {
            byte[] signature;
            using (var rsaCert = GetRsaCertificate())
            {
                var key = rsaCert.PrivateKey;

                var contentInfo = new ContentInfo(bytesToHash);
                var signedCms = new SignedCms(contentInfo, false);
                CmsSigner cmsSigner = new CmsSigner(rsaCert);
                cmsSigner.SignedAttributes.Add(new Pkcs9SigningTime(DateTime.Now));
                signedCms.ComputeSignature(cmsSigner);
                signature = signedCms.Encode();
                Console.WriteLine($"CMS Sign: {Convert.ToBase64String(signature)}");
            }

            // Создаем SignedCms для декодирования и проверки.
            SignedCms signedCmsVerify = new SignedCms();

            // Декодируем подпись
            signedCmsVerify.Decode(signature);

            // Проверяем подпись
            signedCmsVerify.CheckSignature(true);
        }

        private static X509Certificate2 GetRsaCertificate()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Find(X509FindType.FindBySubjectName, "RsaTestCert", false)[0];
            }
        }
    }
}
