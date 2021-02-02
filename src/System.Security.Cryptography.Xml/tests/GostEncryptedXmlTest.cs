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

        //private static Gost3410CryptoServiceProvider GetPkGostProvider()
        //{
        //    CspParameters cpsParams = new CspParameters()
        //    {
        //        KeyContainerName = $"\\\\.\\HDImage\\0000_xml_test_{Guid.NewGuid()}",
        //        KeyPassword = new SecureString(),
        //        Flags = CspProviderFlags.NoPrompt,
        //        ProviderName = "Crypto-Pro GOST R 34.10-2001 Cryptographic Service Provider",
        //        ProviderType = 75,
        //    };
        //    return new Gost3410CryptoServiceProvider(cpsParams);
        //}

        private static Gost3410_2012_256CryptoServiceProvider GetGost2012_256Provider()
        {
            CspParameters cpsParams = new CspParameters(
                80,
                "",
                "\\\\.\\HDIMAGE\\G2012256");
            return new Gost3410_2012_256CryptoServiceProvider(cpsParams);
        }

        //private static Gost3410_2012_256CryptoServiceProvider GetPkGost2012_256Provider()
        //{
        //    CspParameters cpsParams = new CspParameters()
        //    {
        //        KeyContainerName = $"\\\\.\\HDImage\\0000_xml_test_{Guid.NewGuid()}",
        //        KeyPassword = new SecureString(),
        //        Flags = CspProviderFlags.NoPrompt,
        //        ProviderName = "Crypto-Pro GOST R 34.10-2012 Cryptographic Service Provider",
        //        ProviderType = 80,
        //    };
        //    return new Gost3410_2012_256CryptoServiceProvider(cpsParams);
        //}

        private static Gost3410_2012_512CryptoServiceProvider GetGost2012_512Provider()
        {
            CspParameters cpsParams = new CspParameters(
                81,
                "",
                "\\\\.\\HDIMAGE\\G2012512");
            return new Gost3410_2012_512CryptoServiceProvider(cpsParams);
        }

        //private static Gost3410_2012_512CryptoServiceProvider GetPkGost2012_512Provider()
        //{
        //    CspParameters cpsParams = new CspParameters()
        //    {
        //        KeyContainerName = $"\\\\.\\HDImage\\0000_xml_test_{Guid.NewGuid()}",
        //        KeyPassword = new SecureString(),
        //        Flags = CspProviderFlags.NoPrompt,
        //        ProviderName = "Crypto-Pro GOST R 34.10-2012 Strong Cryptographic Service Provider",
        //        ProviderType = 81,
        //    };
        //    return new Gost3410_2012_512CryptoServiceProvider(cpsParams);
        //}
    }
}
