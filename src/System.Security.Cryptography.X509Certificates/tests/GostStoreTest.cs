using Xunit;

namespace System.Security.Cryptography.X509Certificates.Tests
{
    public static class GostStoreTest
    {
        [Fact]
        public static void OpenGostCertFromStore()
        {
            using (
                var store = new X509Store(
                    StoreName.My,
                    StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var cert = store.Certificates.Find(X509FindType.FindBySubjectName, "G2012256", false)[0];

                Assert.Equal(
                    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256",
                    cert.PrivateKey.SignatureAlgorithm);
            }
        }
        [Fact]
        public static void OpenGostCertFromStoreByThumbprint()
        {
            using (
                var store = new X509Store(
                    StoreName.My,
                    StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                var cert = store.Certificates.Find(X509FindType.FindByThumbprint, "5cc5be3498288fad3962eabceaf8e14a65e257ff", false)[0];

                Assert.Equal(
                    "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256",
                    cert.PrivateKey.SignatureAlgorithm);
            }
        }
    }
}
