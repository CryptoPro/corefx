using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Xml;
using Xunit;

namespace System.Security.Cryptography.Xml.Tests
{
    public class GostEncryptedXmlTest
    {
        [Fact]
        public void Encrypt2001()
        {
            using (Gost3410 gost = GetGostProvider())
            {
                Encrypt(gost);
            }
        }

        [Fact]
        public void Encrypt2012_256()
        {
            using (Gost3410_2012_256 gost = GetGost2012_256Provider())
            {
                Encrypt(gost);
            }
        }

        [Fact]
        public void Encrypt2012_512()
        {
            using (Gost3410_2012_512 gost = GetGost2012_512Provider())
            {
                Encrypt(gost);
            }
        }

        [Fact]
        public void Encrypt2001Certificate()
        {
            using (var cert = GetGost2001Certificate())
            {
                Encrypt(cert);
                Decrypt($"d_encrypted_{cert.SubjectName}.xml", $"d_decrypted_{cert.SubjectName}.xml", cert);
            }
        }

        [Fact]
        public void Encrypt2012_256Certificate()
        {
            using (var cert = GetGost2012_256Certificate())
            {
                Encrypt(cert);
                Decrypt($"d_encrypted_{cert.SubjectName}.xml", $"d_decrypted_{cert.SubjectName}.xml", cert);
            }
        }

        [Fact]
        public void Encrypt2012_512Certificate()
        {
            using (var cert = GetGost2012_512Certificate())
            {
                Encrypt(cert);
                Decrypt($"d_encrypted_{cert.SubjectName}.xml", $"d_decrypted_{cert.SubjectName}.xml", cert);
            }
        }

        private void Encrypt(AsymmetricAlgorithm gostKey)
        {
            if (gostKey is Gost3410 gost3410)
            {
                Console.WriteLine("Секретный ключ получен.");
                // и получаем открытый ключ.
                Gost3410Parameters publicKey = gost3410.ExportParameters(false);

                Console.WriteLine("На стороне отправителя...");
                // Полученный открытый ключ передаем отправителю сообщения.
                using (Gost3410CryptoServiceProvider pubKey = new Gost3410CryptoServiceProvider())
                {

                    pubKey.ImportParameters(publicKey);
                    Console.WriteLine("Открытый ключ получен.");

                    // Создаем Xml файл для зашифрования.
                    CreateSomeXml("ato_encrypt_2001.xml");
                    Console.WriteLine("Создан новый XML файл.");

                    // Зашифровываем узел, заданный xpath выражением, XML документа 
                    // ato_encrypt.xml в документ a_encrypted.xml
                    // Для зашифрования используется открытый ключ pubKey.
                    Encrypt("ato_encrypt_2001.xml", "a_encrypted_2001.xml",
                        "//SomeNode[@ToEncrypt='true']",
                        "EncryptedElement1", pubKey, "KeyAlias");
                    Console.WriteLine("Узел XML файла зашифрован.");

                    Console.WriteLine("На стороне получателя...");

                    Decrypt("a_encrypted_2001.xml", "a_decrypted_2001.xml", gost3410, "KeyAlias");
                }
            }
            else if (gostKey is Gost3410_2012_256 gost3410_2012_256)
            {
                Console.WriteLine("Секретный ключ получен.");
                // и получаем открытый ключ.
                Gost3410Parameters publicKey = gost3410_2012_256.ExportParameters(false);

                Console.WriteLine("На стороне отправителя...");
                // Полученный открытый ключ передаем отправителю сообщения.
                using (Gost3410_2012_256CryptoServiceProvider pubKey = new Gost3410_2012_256CryptoServiceProvider())
                {
                    pubKey.ImportParameters(publicKey);
                    Console.WriteLine("Открытый ключ получен.");

                    // Создаем Xml файл для зашифрования.
                    CreateSomeXml("ato_encrypt_2012_256.xml");
                    Console.WriteLine("Создан новый XML файл.");

                    // Зашифровываем узел, заданный xpath выражением, XML документа 
                    // ato_encrypt.xml в документ a_encrypted.xml
                    // Для зашифрования используется открытый ключ pubKey.
                    Encrypt("ato_encrypt_2012_256.xml", "a_encrypted_2012_256.xml",
                        "//SomeNode[@ToEncrypt='true']",
                        "EncryptedElement1", pubKey, "KeyAlias");
                    Console.WriteLine("Узел XML файла зашифрован.");

                    Console.WriteLine("На стороне получателя...");

                    Decrypt("a_encrypted_2012_256.xml", "a_decrypted_2012_256.xml", gost3410_2012_256, "KeyAlias");
                }
            }
            else if (gostKey is Gost3410_2012_512 gost3410_2012_512)
            {
                Console.WriteLine("Секретный ключ получен.");
                // и получаем открытый ключ.
                Gost3410Parameters publicKey = gost3410_2012_512.ExportParameters(false);

                Console.WriteLine("На стороне отправителя...");
                // Полученный открытый ключ передаем отправителю сообщения.
                using (Gost3410_2012_512CryptoServiceProvider pubKey = new Gost3410_2012_512CryptoServiceProvider())
                {
                    pubKey.ImportParameters(publicKey);
                    Console.WriteLine("Открытый ключ получен.");

                    // Создаем Xml файл для зашифрования.
                    CreateSomeXml("ato_encrypt_2012_512.xml");
                    Console.WriteLine("Создан новый XML файл.");

                    // Зашифровываем узел, заданный xpath выражением, XML документа 
                    // ato_encrypt.xml в документ a_encrypted.xml
                    // Для зашифрования используется открытый ключ pubKey.
                    Encrypt("ato_encrypt_2012_512.xml", "a_encrypted_2012_512.xml",
                        "//SomeNode[@ToEncrypt='true']",
                        "EncryptedElement1", pubKey, "KeyAlias");
                    Console.WriteLine("Узел XML файла зашифрован.");

                    Console.WriteLine("На стороне получателя...");

                    Decrypt("a_encrypted_2012_512.xml", "a_decrypted_2012_512bui.xml", gost3410_2012_512, "KeyAlias");
                }
            }
            else
            {
                throw new NotSupportedException();
            }
            
            Console.WriteLine("XML документ расшифрован.");
        }

        // Зашифрование узла XML документа на ассиметричном ключе
        private static void Encrypt(string srcName, string destName,
            string xpath, string EncryptionElementID, AsymmetricAlgorithm alg,
            string KeyName)
        {
            // Создаем новый объект xml документа.
            XmlDocument xmlDoc = new XmlDocument();

            // Пробельные символы участвуют в вычислении подписи и должны быть сохранены для совместимости с другими реализациями
            xmlDoc.PreserveWhitespace = true;

            // Загружаем в объект созданный XML документ.
            xmlDoc.Load(srcName);

            // Ищем заданный элемент для заширования.
            XmlElement elementToEncrypt = xmlDoc.SelectSingleNode(xpath)
                as XmlElement;
            if (elementToEncrypt == null)
                throw new XmlException("Узел не найден");

            // Создаем случайный симметричный ключ.
            // В целях безопасности удаляем ключ из памяти после использования.
            using (Gost28147CryptoServiceProvider sessionKey =
                new Gost28147CryptoServiceProvider())
            {
                // Создаем объект класса EncryptedXml и используем 
                // его для зашифрования узла на случайной симметричном ключе.
                EncryptedXml eXml = new EncryptedXml();

                // Зашифровываем элемент на сессионном ключе.
                byte[] encryptedElement = eXml.EncryptData(elementToEncrypt,
                    sessionKey, false);

                // Создаем объект EncryptedData и заполняем его
                // необходимой информацией.
                EncryptedData edElement = new EncryptedData();
                // Тип элемента зашифрованный узел
                edElement.Type = EncryptedXml.XmlEncElementUrl;
                // Созданный элемент помечаем EncryptionElementID
                edElement.Id = EncryptionElementID;

                // Заполняем алгоритм зашифрования данных. 
                // Он будет использован при расшифровании.
                edElement.EncryptionMethod = new EncryptionMethod(
                    EncryptedXml.XmlEncGost28147Url);

                // Зашифровываем сессионный ключ и добавляем эти зашифрованные данные
                // к узлу EncryptedKey.
                EncryptedKey ek = new EncryptedKey();
                byte[] encryptedKey;

                if (alg is Gost3410 gost3410)
                {
                    encryptedKey = EncryptedXml.EncryptKey(sessionKey, gost3410);
                }
                else if (alg is Gost3410_2012_256 gost3410_2012_256)
                {
                    encryptedKey = EncryptedXml.EncryptKey(sessionKey, gost3410_2012_256);
                }
                else if (alg is Gost3410_2012_512 gost3410_2012_512)
                {
                    encryptedKey = EncryptedXml.EncryptKey(sessionKey, gost3410_2012_512);
                }
                else
                {
                    throw new NotSupportedException();
                }
                ek.CipherData = new CipherData(encryptedKey);
                ek.EncryptionMethod = new EncryptionMethod(
                    EncryptedXml.XmlEncGostKeyTransportUrl);

                // Создаем элемент DataReference для KeyInfo.
                // Эта необязательная операция позволяет указать
                // какие данные используют данный ключ.
                // XML документ может содержвать несколько
                // элементов EncryptedData с различными ключами.
                DataReference dRef = new DataReference();

                // Указываем URI EncryptedData.
                // Для этого используем ранее проставленную ссылку
                // EncryptionElementID
                dRef.Uri = "#" + EncryptionElementID;

                // Добавляем к EncryptedKey ссылку на зашифрованные 
                // данные.
                ek.AddReference(dRef);

                // Создаем новую ссылку на ключ.
                edElement.KeyInfo = new KeyInfo();

                // Добавляем ссылку на зашифрованный ключ к 
                // зашифрованным данным.
                edElement.KeyInfo.AddClause(new KeyInfoEncryptedKey(ek));

                // Указываем имя ассиметричного ключа.

                // Создаем новый элемент KeyInfoName 
                KeyInfoName kin = new KeyInfoName();

                // Указываем имя ассиметричного ключа.
                kin.Value = KeyName;

                // Добавляем элемент KeyInfoName к
                // объекту EncryptedKey.
                ek.KeyInfo.AddClause(kin);

                // Добавляем зашифрованные данные 
                // к объекту EncryptedData.
                edElement.CipherData.CipherValue = encryptedElement;

                // Заменяем исходный узел на зашифрованный.
                EncryptedXml.ReplaceElement(elementToEncrypt,
                    edElement, false);

                // Сохраняем зашифрованный документ.
                xmlDoc.Save(destName);
            }
        }

        // Расшифрование узла XML документа на ассиметричном ключе
        private static void Decrypt(string srcName, string destName,
            AsymmetricAlgorithm alg, string KeyName)
        {
            // Создаем новый объект xml документа.
            XmlDocument xmlDoc = new XmlDocument();

            // Пробельные символы участвуют в вычислении подписи и должны быть сохранены для совместимости с другими реализациями
            xmlDoc.PreserveWhitespace = true;

            // Загружаем в объект созданный XML документ.
            xmlDoc.Load(srcName);

            // Создаем объект EncryptedXml.
            EncryptedXml exml = new EncryptedXml(xmlDoc);

            // Добавляем отображение имен в ключи.
            // Нижеследующий метод сможет расшифровать
            // только те документы, для которых будет 
            // найдены соответсвующие ключи.

            if (alg is Gost3410 gost3410)
            {
                exml.AddKeyNameMapping(KeyName, gost3410);
            }
            else if (alg is Gost3410_2012_256 gost3410_2012_256)
            {
                exml.AddKeyNameMapping(KeyName, gost3410_2012_256);
            }
            else if (alg is Gost3410_2012_512 gost3410_2012_512)
            {
                exml.AddKeyNameMapping(KeyName, gost3410_2012_512);
            }
            else
            {
                throw new NotSupportedException();
            }

            // Расшифровываем зашифрованные элементы.
            exml.DecryptDocument();

            // Сохраняем расшифрованный документ.
            xmlDoc.Save(destName);
        }

        private void Encrypt(X509Certificate2 cert)
        {
            // Создаем тестовый XML документ.
            CreateSomeXml($"doc_to_encrypt_{cert.SubjectName}.xml");

            // Создаем объект XmlDocument.
            XmlDocument xmlDoc = new XmlDocument();

            // Загружаем XML файл в объект XmlDocument.
            xmlDoc.PreserveWhitespace = true;
            xmlDoc.Load($"doc_to_encrypt_{cert.SubjectName}.xml");

            // Шифруем узел SomeNode, который содержит атрибут ToEncrypt со значением true
            Encrypt(xmlDoc, "//SomeNode[@ToEncrypt='true']", cert);

            // Сохраняем XML документ.
            xmlDoc.Save($"d_encrypted_{cert.SubjectName}.xml");
        }


        // Зашифрование узла в адрес абонента, заданного сертификатом 
        // получателя.
        static void Encrypt(XmlDocument Doc, string xpath,
            X509Certificate2 Cert)
        {
            // Ищем заданный элемент для заширования.
            XmlElement elementToEncrypt = Doc.SelectSingleNode(xpath) as XmlElement;
            if (elementToEncrypt == null)
                throw new XmlException("Узел не найден");

            // Создаем объект EncryptedXml для  
            // шифрования XmlElement
            EncryptedXml eXml = new EncryptedXml();

            // Шифруем элемент на сертификате.
            EncryptedData edElement = eXml.Encrypt(elementToEncrypt, Cert);

            // Заменяем исходный элемент XML документа зашифрованным.
            EncryptedXml.ReplaceElement(elementToEncrypt, edElement, false);
        }

        static void Decrypt(string srcName, string destName, X509Certificate2 cert)
        {
            // Создаем новый объект xml документа.
            XmlDocument xmlDoc = new XmlDocument();

            // Пробельные символы участвуют в вычислении подписи и должны быть сохранены для совместимости с другими реализациями
            xmlDoc.PreserveWhitespace = true;

            // Загружаем в объект созданный XML документ.
            xmlDoc.Load(srcName);

            // Создаем новый объект EncryptedXml по XML документу.
            EncryptedXml exml = new EncryptedXml(xmlDoc);

            // Небольшие хаки, чтобы не устанавливать серт в хранилище
            {
                var ns = new XmlNamespaceManager(xmlDoc.NameTable);
                ns.AddNamespace("ki", "http://www.w3.org/2000/09/xmldsig#");
                ns.AddNamespace("ek", "http://www.w3.org/2001/04/xmlenc#");
                var keyName = Convert.ToBase64String(cert.Export(X509ContentType.Cert));
                var keyInfoNode = xmlDoc.SelectSingleNode("//ki:KeyInfo/ek:EncryptedKey/ki:KeyInfo", ns);
                if (keyInfoNode == null)
                {
                    throw new InvalidOperationException("Неверный формат зашифрованного XML-документа.");
                }

                if (keyInfoNode.InnerText.Equals(keyName, StringComparison.InvariantCultureIgnoreCase))
                {
                    keyInfoNode.InnerXml = $"<KeyName>{keyName}</KeyName>";
                }
                exml.AddKeyNameMapping(keyName, cert.PrivateKey);
                exml.Recipient = keyName;
            }

            // Расшифровываем зашифрованные узлы XML документа.
            exml.DecryptDocument();

            // Сохраняем расшифрованный документ.
            xmlDoc.Save(destName);
        }

        // Тестовый документ для зашифрования / расшифрования.
        private static string SourceDocument = "" +
            "<MyXML Encrypted=\"false\">" +
            "    <SomeNode ToEncrypt=\"false\">" +
                    "Here is some public data.</SomeNode>" +
            "    <SomeNode ToEncrypt=\"true\">" +
                    "Here is some data to encrypt.</SomeNode>" +
            "</MyXML>";

        // Создание тестового XML документа.
        static void CreateSomeXml(string FileName)
        {
            // Создать документ по строке
            XmlDocument document = new XmlDocument();
            document.LoadXml(SourceDocument);

            // Сохранить шифруемый документ в файле.
            using (XmlTextWriter xmltw = new XmlTextWriter(FileName,
                new UTF8Encoding(false)))
            {
                xmltw.WriteStartDocument();
                document.WriteTo(xmltw);
            }
        }

        private static Gost3410CryptoServiceProvider GetGostProvider()
        {
            CspParameters cpsParams = new CspParameters(
                75,
                "",
                "\\\\.\\HDIMAGE\\G2001256");
            return new Gost3410CryptoServiceProvider(cpsParams);
        }

        private static Gost3410_2012_256CryptoServiceProvider GetGost2012_256Provider()
        {
            CspParameters cpsParams = new CspParameters(
                80,
                "",
                "\\\\.\\HDIMAGE\\G2012256");
            return new Gost3410_2012_256CryptoServiceProvider(cpsParams);
        }

        private static Gost3410_2012_512CryptoServiceProvider GetGost2012_512Provider()
        {
            CspParameters cpsParams = new CspParameters(
                81,
                "",
                "\\\\.\\HDIMAGE\\G2012512");
            return new Gost3410_2012_512CryptoServiceProvider(cpsParams);
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
