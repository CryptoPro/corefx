using System.Globalization;
using System.IO;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using System.Xml.XPath;
using Xunit;

namespace System.Security.Cryptography.Xml.Tests
{
    public class GostSignedXmlTest
    {
        [Fact]
        public void Sign2001()
        {
            var rawXml2001 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><MyXML><ElementToSign>Here is some data to sign.</ElementToSign></MyXML>";
            var doc = new XmlDocument();
            // Сохраняем все пробельные символы, они важны при проверке 
            // подписи.
            doc.PreserveWhitespace = true;
            doc.LoadXml(rawXml2001);

            var cert = GetGost2001Certificate();

            SignXmlFile(doc, cert.PrivateKey, cert, SignedXml.XmlDsigGost3411_2012_256Url);

            var result = ValidateXmlFIle(doc);
            Assert.True(result);
        }

        [Fact]
        public void Sign2012_256()
        {
            var rawXml2012_256 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><MyXML><ElementToSign>Here is some data to sign.</ElementToSign></MyXML>";
            var doc = new XmlDocument();
            // Сохраняем все пробельные символы, они важны при проверке 
            // подписи.
            doc.PreserveWhitespace = true;
            doc.LoadXml(rawXml2012_256);

            var cert = GetGost2012_256Certificate();

            SignXmlFile(doc, cert.PrivateKey, cert, SignedXml.XmlDsigGost3411_2012_256Url);

            var result = ValidateXmlFIle(doc);
            Assert.True(result);
        }

        [Fact]
        public void Sign2012_512()
        {
            var rawXml2012_512 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><MyXML><ElementToSign>Here is some data to sign.</ElementToSign></MyXML>";
            var doc = new XmlDocument();
            // Сохраняем все пробельные символы, они важны при проверке 
            // подписи.
            doc.PreserveWhitespace = true;
            doc.LoadXml(rawXml2012_512);

            var cert = GetGost2012_512Certificate();

            SignXmlFile(doc, cert.PrivateKey, cert, SignedXml.XmlDsigGost3411_2012_256Url);

            var result = ValidateXmlFIle(doc);
            Assert.True(result);
        }

        [Fact]
        public void Verify2001()
        {
            var rawXml2001 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><MyXML Signed=\"true\"><ElementToSign Signed=\"true\">Here is some data to sign.</ElementToSign><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /></Transforms><DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411\" /><DigestValue>zPlpay6cswDZcJP+UiPemVWUFj4/cUaekOMZ3J8Oxt0=</DigestValue></Reference></SignedInfo><SignatureValue>3zWR/2WP3iPgDJGDsEcyxslBDivMIpR4xJW+5FlnWVjIle698eBHcVmXN56+ANbkKQNEppZH/eYbhEuPqowz3A==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIBdTCCASSgAwIBAgIQEqJolTJ9uptHeW8F5+KVNDAIBgYqhQMCAgMwGDEWMBQGA1UEAwwNR29zdDIwMDFfMjAxOTAgFw0xOTA3MDExMjMwNTdaGA8yMTAwMDMyMDA3MzEwMFowGDEWMBQGA1UEAwwNR29zdDIwMDFfMjAxOTBjMBwGBiqFAwICEzASBgcqhQMCAiQABgcqhQMCAh4BA0MABEAoaFZtEY1XDGRRdPBuGZkufp6ZNDrG49Tav1eCRZg/2QW7tkBdBXFSAdx+ZipboqgeJtaMhVujj51KkwpR6MnBo0YwRDAOBgNVHQ8BAf8EBAMCBeAwEwYDVR0lBAwwCgYIKwYBBQUHAwIwHQYDVR0OBBYEFJa6+pSxmsk9V6rDs6GsYbj/lFKgMAgGBiqFAwICAwNBAAwv9awAZzVilC7m29cP3ivFy8j4x31CsWfsyc3J/ZdJEEYZyVMHUvR+ym9/B1ODs/AF8tQ0nQgVQU5dOCHq4EQ=</X509Certificate></X509Data></KeyInfo></Signature></MyXML>";
            var doc = new XmlDocument();
            // Сохраняем все пробельные символы, они важны при проверке 
            // подписи.
            doc.PreserveWhitespace = true;
            doc.LoadXml(rawXml2001);
            var result = ValidateXmlFIle(doc);
            Assert.True(result);
        }

        [Fact]
        public void Verify2012_256()
        {
            var rawXml2012_256 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><MyXML Signed=\"true\"><ElementToSign Signed=\"true\">Here is some data to sign.</ElementToSign><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /></Transforms><DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34112012-256\" /><DigestValue>AJurr2ph8YjCraU6VFAeTKXKM3zZtz4gHgN0+gzE5y8=</DigestValue></Reference></SignedInfo><SignatureValue>fbjm76Pe8oe++5udjiqVolYUBmwue11qdxdudGSjw+7TNevOQ4NsGkSYaK/zbsXntZyGGk8vNzJiIpqQH7NLdw==</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIBhDCCATGgAwIBAgIQdRGdjFEFWqJFdK3uXftqvDAKBggqhQMHAQEDAjAdMRswGQYDVQQDDBJHb3N0XzIwMTJfMjU2X1Rlc3QwHhcNMTcxMTI4MDc1NjM1WhcNNDAwMzIwMDczMTAwWjAdMRswGQYDVQQDDBJHb3N0XzIwMTJfMjU2X1Rlc3QwZjAfBggqhQMHAQEBATATBgcqhQMCAiQABggqhQMHAQECAgNDAARAA1ZjRyfGkhalAO5hgXvYUvs8S3Xkap98Fp9RfqA7L+BV0391rHPL6d0uGx4WsBmM9G802YJgDZCuiMyKAgi5R6NGMEQwDgYDVR0PAQH/BAQDAgXgMBMGA1UdJQQMMAoGCCsGAQUFBwMCMB0GA1UdDgQWBBR1pExePljgg5daru/pCaFbqIYHvTAKBggqhQMHAQEDAgNBAIekQ/6QdH47xOGFMN3lEMmFi503SmGZ8o7sIjBAjBeWrHNUsoGXeVl46KZbCYtrw7mGxyVn6iUmFGLXYD22He8=</X509Certificate></X509Data></KeyInfo></Signature></MyXML>";
            var doc = new XmlDocument();
            // Сохраняем все пробельные символы, они важны при проверке 
            // подписи.
            doc.PreserveWhitespace = true;
            doc.LoadXml(rawXml2012_256);
            var result = ValidateXmlFIle(doc);
            Assert.True(result);
        }

        [Fact]
        public void Verify2012_512()
        {
            var rawXml2012_512 = "<?xml version=\"1.0\" encoding=\"utf-8\"?><MyXML Signed=\"true\"><ElementToSign Signed=\"true\">Here is some data to sign.</ElementToSign><Signature xmlns=\"http://www.w3.org/2000/09/xmldsig#\"><SignedInfo><CanonicalizationMethod Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /><SignatureMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512\" /><Reference URI=\"\"><Transforms><Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\" /><Transform Algorithm=\"http://www.w3.org/TR/2001/REC-xml-c14n-20010315\" /></Transforms><DigestMethod Algorithm=\"urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr3411\" /><DigestValue>zPlpay6cswDZcJP+UiPemVWUFj4/cUaekOMZ3J8Oxt0=</DigestValue></Reference></SignedInfo><SignatureValue>UZ585ij9MdTC1uN96LQ6bq0IWGQ6Cei5MOEyaz/ywQJyBBxLWld7SNbd+ZOyd1jcJwfMDG/v1dctJjByZgsveQR7QnD7Lq6lp25sGPaReXEVs1xaHT0WIEK5TwBGH/4WuXyrGgp9qSdy4ZW8zDAGPSpfuIUMpJn21wdxUG/qUWQ=</SignatureValue><KeyInfo><X509Data><X509Certificate>MIIChTCCAfGgAwIBAgIBATAKBggqhQMHAQEDAzA1MSAwHgYJKoZIhvcNAQkBFhF0ZXN0QGNyeXB0b3Byby5ydTERMA8GA1UEAwwIRzIwMTI1MTIwHhcNMTkwMTI0MTMyMzEwWhcNMzAwMTAxMTMyMzEwWjA1MSAwHgYJKoZIhvcNAQkBFhF0ZXN0QGNyeXB0b3Byby5ydTERMA8GA1UEAwwIRzIwMTI1MTIwgaowIQYIKoUDBwEBAQIwFQYJKoUDBwECAQIBBggqhQMHAQECAwOBhAAEgYAMFoJl3zaAWAX2Yal4Bmu5xzbSHjI2tzJigQhbdaZkwk5+joJDz9AvWuW0DtNDwvk2zVneF8kX5wjLD1weSRa/VSJUbUbJgvCoDvPybgwVP1xnxnYpXEshIKEQlOy781RsnriXumMmaymCwZ2ddzq9hs5joEOWpPRwL7mfmcB5v6OBnzCBnDAdBgNVHQ4EFgQUas4KM9kNpuBiRVmPR1Q8nzvAitIwCwYDVR0PBAQDAgHGMA8GA1UdEwQIMAYBAf8CAQEwXQYDVR0BBFYwVIAUas4KM9kNpuBiRVmPR1Q8nzvAitKhOaQ3MDUxIDAeBgkqhkiG9w0BCQEWEXRlc3RAY3J5cHRvcHJvLnJ1MREwDwYDVQQDDAhHMjAxMjUxMoIBATAKBggqhQMHAQEDAwOBgQBkl84we9KxdbjEPlZpUvnjl48Ob+v0NCPjt/azci+y5lEU0FKvSrCu3Raz3AoviMiiPH7oA1OsANgfQ43elS6J9g9B7xHGXJyM6B4JHC5W1w2H27V2WkbDsWLJpELvqjj+fLA2sFLJX/DuEcSjRTibzypKUuwJEDMIvMo83WVEVw==</X509Certificate></X509Data></KeyInfo></Signature></MyXML>";
            var doc = new XmlDocument();
            // Сохраняем все пробельные символы, они важны при проверке 
            // подписи.
            doc.PreserveWhitespace = true;
            doc.LoadXml(rawXml2012_512);
            var result = ValidateXmlFIle(doc);
            Assert.True(result);
        }

        static XmlDocument SignXmlFile(
            XmlDocument doc,
            AsymmetricAlgorithm Key, 
            X509Certificate Certificate, 
            string DigestMethod = SignedXml.XmlDsigGost3411_2012_256Url)
        {
            // Создаем объект SignedXml по XML документу.
            SignedXml signedXml = new SignedXml(doc);

            // Добавляем ключ в SignedXml документ. 
            signedXml.SigningKey = Key;

            // Создаем ссылку на node для подписи.
            // При подписи всего документа проставляем "".
            Reference reference = new Reference();
            reference.Uri = "";

            // Явно проставляем алгоритм хэширования,
            // по умолчанию SHA1.
            reference.DigestMethod = DigestMethod;

            // Добавляем transform на подписываемые данные
            // для удаления вложенной подписи.
            XmlDsigEnvelopedSignatureTransform env =
                new XmlDsigEnvelopedSignatureTransform();
            reference.AddTransform(env);

            // Добавляем СМЭВ трансформ.
            // начиная с .NET 4.5.1 для проверки подписи, необходимо добавить этот трансформ в довернные:
            // signedXml.SafeCanonicalizationMethods.Add("urn://smev-gov-ru/xmldsig/transform");
            XmlDsigSmevTransform smev =
                new XmlDsigSmevTransform();
            reference.AddTransform(smev);

            // Добавляем transform для канонизации.
            XmlDsigC14NTransform c14 = new XmlDsigC14NTransform();
            reference.AddTransform(c14);

            // Добавляем ссылку на подписываемые данные
            signedXml.AddReference(reference);

            // Создаем объект KeyInfo.
            KeyInfo keyInfo = new KeyInfo();

            // Добавляем сертификат в KeyInfo
            keyInfo.AddClause(new KeyInfoX509Data(Certificate));

            // Добавляем KeyInfo в SignedXml.
            signedXml.KeyInfo = keyInfo;

            // Можно явно проставить алгоритм подписи: ГОСТ Р 34.10.
            // Если сертификат ключа подписи ГОСТ Р 34.10
            // и алгоритм ключа подписи не задан, то будет использован
            // XmlDsigGost3410Url
            // signedXml.SignedInfo.SignatureMethod =
            //     CPSignedXml.XmlDsigGost3410_2012_256Url;

            // Вычисляем подпись.
            signedXml.ComputeSignature();

            // Получаем XML представление подписи и сохраняем его 
            // в отдельном node.
            XmlElement xmlDigitalSignature = signedXml.GetXml();

            // Добавляем node подписи в XML документ.
            doc.DocumentElement.AppendChild(doc.ImportNode(
                xmlDigitalSignature, true));

            // При наличии стартовой XML декларации ее удаляем
            // (во избежание повторного сохранения)
            if (doc.FirstChild is XmlDeclaration)
            {
                doc.RemoveChild(doc.FirstChild);
            }

            return doc;
        }

        static bool ValidateXmlFIle(XmlDocument xmlDocument)
        {
            // Ищем все node "Signature" и сохраняем их в объекте XmlNodeList
            XmlNodeList nodeList = xmlDocument.GetElementsByTagName(
                "Signature", SignedXml.XmlDsigNamespaceUrl);

            // Проверяем все подписи.
            bool result = true;
            for (int curSignature = 0; curSignature < nodeList.Count; curSignature++)
            {
                // Создаем объект SignedXml для проверки подписи документа.
                SignedXml signedXml = new SignedXml(xmlDocument);

                // начиная с .NET 4.5.1 для проверки подписи, необходимо добавить СМЭВ transform в довернные:

                signedXml.SafeCanonicalizationMethods.Add("urn://smev-gov-ru/xmldsig/transform");

                // Загружаем узел с подписью.
                signedXml.LoadXml((XmlElement)nodeList[curSignature]);

                // Проверяем подпись и выводим результат.
                result &= signedXml.CheckSignature();
            }
            return result;
        }

        private static X509Certificate2 GetGost2001Certificate()
        {
            var certString = "MIIEkQIBAzCCBE0GCSqGSIb3DQEHAaCCBD4EggQ6MIIENjCCAe8GCSqGSIb3DQEHAaCCAeAEggHcMIIB2DCCAdQGCyqGSIb3DQEMCgECoIGyMIGvMCQGCiqGSIb3DQEMAVAwFgQQP1iL6CvSFmbGkNXVfY/niQICB9AEgYayEwuTnhY/gieQunKB/rMWblcGkezPH/wUFjxfWmEg+jd0/3vVFwn1WzVF9yqFozkLeHpgHRp/I/axw6xQIr/Zh3RnOHVUUyIpH8KQLee7KHN/WHw2Az9/tZ5KJymlOhU56T7h2hcgzS3OimcHe/QxcXPXVFjPo3qA3MSTsZC+XGhNVr5nzDGCAQ4wEwYJKoZIhvcNAQkVMQYEBAEAAAAwbwYJKoZIhvcNAQkUMWIeYAAwADAAMAAwAF8AdABpAG4AeQBDAEEAXwBiADMANAA3ADQANAA2AGYALQBlADQANQA5AC0ANAA0AGUAZQAtADgANwAzAGUALQA1ADkAMQAzADMANABjAGYAYwBiADYANDCBhQYJKwYBBAGCNxEBMXgedgBDAHIAeQBwAHQAbwAtAFAAcgBvACAARwBPAFMAVAAgAFIAIAAzADQALgAxADAALQAyADAAMAAxACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFMAZQByAHYAaQBjAGUAIABQAHIAbwB2AGkAZABlAHIwggI/BgkqhkiG9w0BBwagggIwMIICLAIBADCCAiUGCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECOP8dKVASVWCAgIH0ICCAfgrSG8VWCafz/3gwmqrP5b1AQNEwAhAiEuA/ekn4LdHXMJo25FV6YeLQ3ECM27a7eUMyoDUcH3iL5l46cFLSNo9eZJADmz8W2L0SmQNbSdvbQdMKkG02M5BK1nHni4CRprG+fuOEppFp6Yr2crdhVzvre0eMCdMkY22oj8jbBqnrvv2EEC+Ays4urnPGFPtu7GSaJA5Gv5Z9pCdNYtXBePbLAcDYpJhDS9JVks2EcmJd8aDknjZ2CV01mOSew1UO6TOvdxhMmQL4sX5769HVHznbuC+zBT+7zS58lGmG6trselhp4hPAUxVa0NaCj0TvrznYze/NAg1DX3UcBSkQWJywCFdgK84DfkyxhImr7tnq6xEu/1WqbWcexYRSzXrwz8QTDYThHLt4sh1NbCv/O5g2yOHIVbbWNwr3rxFMsAvaw+DOqd48ooH7qccQiu7vhcZ2DYnmvH3LvG7ZL9IerzAwIYAutlSlnaldVFRDiTWH69taG+ZBtz4ZHVJ0dluLkQelI+zdzmSA7egmdx/8XvU7L0rCJ4BTxJwotip4y+9urzcGgc6syeLtkrklu8vpeyqIKnBW9ADTAW7AoM5eWH5OuAHSNdiqeUwSKfoN+LuVg/zkg0I9JTzcPeKvqGQEIePBXv/8sHL1wnxkq2w2dwok8ueUEL4EHcwOzAfMAcGBSsOAwIaBBQ78gWnC938VfbaWdlz6Sz1F+0vywQU0acvRnrD3gv6phId1uchQ6cJUcwCAgfQ";
            var certBytes = Convert.FromBase64String(certString);
            return new X509Certificate2(certBytes, new SecureString(), X509KeyStorageFlags.CspNoPersistKeySet);             
        }

        private static X509Certificate2 GetGost2012_256Certificate()
        {
            var certString = "MIIElgIBAzCCBFIGCSqGSIb3DQEHAaCCBEMEggQ/MIIEOzCCAfQGCSqGSIb3DQEHAaCCAeUEggHhMIIB3TCCAdkGCyqGSIb3DQEMCgECoIG3MIG0MCQGCiqGSIb3DQEMAVAwFgQQFSTL4JwKpr9FOV/+/4gnJAICB9AEgYvN9atf6pZE14hZRb2Oi5aaUM6nxXKFli3wVVjKqwnCUZ8DK7M4wQF2NXgjotHpLh4tFslylyB50X3DNI5o/xWm8dqZp1VZcHiK8r0b1RDUnAkyM+sc8xJdIyNnZn5PWU6tWpXAsoPLIW5rSeRwkHmZQjwa6tnKdxvgNVBHO7tlKcJU1uGIEqZXihUqMYIBDjATBgkqhkiG9w0BCRUxBgQEAQAAADBvBgkqhkiG9w0BCRQxYh5gADAAMAAwADAAXwB0AGkAbgB5AEMAQQBfAGYAZAAwADgANwBhADMANAAtADAANgBmADkALQA0ADUANQA3AC0AYgA2ADQANwAtADgAYQAxAGIAYQAzAGIAMAAxAGYAMwBiMIGFBgkrBgEEAYI3EQExeB52AEMAcgB5AHAAdABvAC0AUAByAG8AIABHAE8AUwBUACAAUgAgADMANAAuADEAMAAtADIAMAAxADIAIABDAHIAeQBwAHQAbwBnAHIAYQBwAGgAaQBjACAAUwBlAHIAdgBpAGMAZQAgAFAAcgBvAHYAaQBkAGUAcjCCAj8GCSqGSIb3DQEHBqCCAjAwggIsAgEAMIICJQYJKoZIhvcNAQcBMBwGCiqGSIb3DQEMAQMwDgQIjc70O2ygnV0CAgfQgIIB+BDNOQCx5kr/deKfWD2NTN5SzaeAJMvrJEypk0B2bcoVC4/AKy7o2qhCYhSPEo09edX18/mek6rJkblskQHvnqSr43cXL6HXDnPHsJUGZ1K0Ryz0O51YGNN7YR/6gDR47LQSsgJuSA/QNtnxQ3w3LVrAVnsYStdpLhwc0eggLfmuay8kidOrWdTTOlt+atv8jJiIlOwVxmqUvQ4fb/ZEu245DYFAnq+fmGSwAP6XgI9BlDh0DXE8P9/YzOoVLOIH0b4pS4aiS/hR47F1aNKSU5cqgiPCR5weoegWkepcDg0MUvjch/U4MfV1KqqYvw4fB56xR6WBLF2ulejy/WsdxqpGJjMEapRI6mmtSE7xQaJZteKcuRGjsIDII/0+EZXDVhf6GeoLsgaLZEIfrKyNnTMC4koH0AVyuqWIQGmpXu7peLag4rUF3MR45Feuy4MQWKzWDq5YY486GX+6CMhj+Dz+Sq3OFKfabQZ0KKcW2aePoRAMWqRRm37mV9qvaoSVkMwinR7gYuIzJJV+zZSMTa1PWdBM5eSQD1pAUUZaoIxdHKx0N6MthKZVNejboiOXgNsvN+WD/SSOqee875g23YGqHILiY2e19cx36BumB5PH2o6Zqj27gH5tleRTfqWCh+3pixKn0gv13uu/YhF7rvyiJDiX/S1rBzA7MB8wBwYFKw4DAhoEFMhLeecis0vAUnraipBtXgAnQmjXBBQE/fQFTkILdeQJN9syMFJ+xA3BdgICB9A=";
            var certBytes = Convert.FromBase64String(certString);
            return new X509Certificate2(certBytes, new SecureString(), X509KeyStorageFlags.CspNoPersistKeySet);
        }

        private static X509Certificate2 GetGost2012_512Certificate()
        {
            var certString = "MIIFUgIBAzCCBQ4GCSqGSIb3DQEHAaCCBP8EggT7MIIE9zCCAigGCSqGSIb3DQEHAaCCAhkEggIVMIICETCCAg0GCyqGSIb3DQEMCgECoIHbMIHYMCQGCiqGSIb3DQEMAVAwFgQQmhBacnheYqD48q00lpbW9wICB9AEga9DwceFmFzTHANkQJ2GCx003azs/OJWENrXiV52F4BBeuSrkrCEEqnyht4kTSIUTpz4bSHi9j4ROEfx9COKWKasIq6/k3wnSOk0JsTK53zjmbJUZvToGJaHPBbXub8aGH1+NrjW44fousdx2vLB7JNGhpeQUk5+OX9Uwpa3xRF/445aGOxLjkNgwRlf2w7haRN6cc+/MLjbHCzbV6EvLNTRSfw6OGWyxv78Xw/te7RyMYIBHjATBgkqhkiG9w0BCRUxBgQEAQAAADBvBgkqhkiG9w0BCRQxYh5gADAAMAAwADAAXwB0AGkAbgB5AEMAQQBfADgAOQAxAGIAMABkAGMAZAAtAGEAMgA0AGEALQA0AGIAOQBhAC0AYQBhADUAYwAtAGYAMQBlADkAMQBkADAAYwA3ADAAMgA0MIGVBgkrBgEEAYI3EQExgYcegYQAQwByAHkAcAB0AG8ALQBQAHIAbwAgAEcATwBTAFQAIABSACAAMwA0AC4AMQAwAC0AMgAwADEAMgAgAFMAdAByAG8AbgBnACAAQwByAHkAcAB0AG8AZwByAGEAcABoAGkAYwAgAFMAZQByAHYAaQBjAGUAIABQAHIAbwB2AGkAZABlAHIwggLHBgkqhkiG9w0BBwagggK4MIICtAIBADCCAq0GCSqGSIb3DQEHATAcBgoqhkiG9w0BDAEDMA4ECAJe5SovWceLAgIH0ICCAoDeeYKaAHgiwFNtT9LZzR38rTp4l8r5P9enJOYwQIaTrLgj3pml4fTrkCraJMr98CSrbyVBSZw9a5YYL/Bph0bj4SGUPzanL9ba5X1JFQ5v0HWrgtAlnuXEFkBigPPXOJ9pbqQNs7fxEJQUqH5hUL8ka/nSYdnzHGQOEBkh/jj2VP7jJoBKzd5VBrYD89NVvd8u5oR5OLScE1pLPTA3fz5NMNT0ln1TckDYINIF80NLdKe0esGJDszW+maGxblGUsaCGhgeNA5Bqz65F0iZXcJO14bUYFrQGvdIaT26F+i5+Ewzg93iJPiiIADxicafDPL65Bl2KMZwRn39GDmXc1J5XEW8EnJo6kzSTn+KVA8h2SQmzEL6xD+nRwyZLclj5zlQbDKiEcJDwYF14aYUK13nOhMcstSTBv98btDyP2zutcH0iqJc65VvLT66GYvqE99M2B6s9JwkCwA4+fn78e/tFwIWppMwEhjapcE+px7H6yl/Qxr7db66uWkMaSLjTAo+znAsb7yLrVsZE+m5Npxm4c93lPAqtpLbjJRpeX5s5YZ275HbQv2zmZcSYcWx8SSq1P4TbPEMd9mCXIyi2dWrh0SE7D8spUSliaME1qCzV6PrXLxQLwsa0P2E4jVmYJbEWGuv/H93mJccDnRCTrppccyP/XMFhrujfLxZJpizi04tciNVG2eV2xbvXXmoneqw4SytR2k+AZCxFd4YvOXQ1R8PxOoODb+O5cH/NSC1kBH8c1bA7ytGuxJFVavAXJZj0vCmoh8A5+Yb/EkETcnpl7Brxo9uPaciRLETi+0mOUp5T2EE18oYVAefkP+t7oS4OkusMkN9REw+GolduOLSMDswHzAHBgUrDgMCGgQUQ0cnR1HhGqQL9NXH9SkMNkptEk4EFI7IBvDVm43Ct8GtY3vyklko+l3eAgIH0A==";
            var certBytes = Convert.FromBase64String(certString);
            return new X509Certificate2(certBytes, new SecureString(), X509KeyStorageFlags.CspNoPersistKeySet);
        }
    }
}
