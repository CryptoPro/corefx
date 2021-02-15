namespace System.Security.Cryptography.Encryption.KeyExchange.Tests
{
    using Xunit;
    using System.Security.Cryptography;
    using System.Text;
    using System.Collections;
    using System.IO;
    using System.Runtime.Serialization.Formatters.Binary;
    using System.Security.Cryptography.X509Certificates;

    public class GostSharedSecretTest
    {
        const string SourceFileName = "src_file_{0}.txt";
        const string EncryptedFileName = "end_file_{0}.txt";
        const string DecryptedFileName = "dec_file_{0}.txt";

        [Fact]
        public void TestFileAgree2001()
        {
            using (var provider = GetGostProvider2001())
            {
                var senderPrivateKey = provider;
                var receiverPublicKey = provider;
                var receiverPrivateKey = provider;

                CreateTestFile("2001");
                // Зашифровываем файл на открытом ключе из сертификата.
                EncryptTestFile(receiverPublicKey, senderPrivateKey);
                // Расшифровываем файл и выводим результат на экран.
                DecryptTestFile(receiverPrivateKey);
            }
        }

        [Fact]
        public void TestFileAgree2012_256()
        {
            using (var provider = GetGostProvider2012_256())
            {
                var senderPrivateKey = provider;
                var receiverPublicKey = provider;
                var receiverPrivateKey = provider;

                CreateTestFile("2012_256");
                // Зашифровываем файл на открытом ключе из сертификата.
                EncryptTestFile(receiverPublicKey, senderPrivateKey);
                // Расшифровываем файл и выводим результат на экран.
                DecryptTestFile(receiverPrivateKey);
            }
        }

        [Fact]
        public void TestFileAgree2012_512()
        {
            using (var provider = GetGostProvider2012_512())
            {
                var senderPrivateKey = provider;
                var receiverPublicKey = provider;
                var receiverPrivateKey = provider;

                CreateTestFile("2012_512");
                // Зашифровываем файл на открытом ключе из сертификата.
                EncryptTestFile(receiverPublicKey, senderPrivateKey);
                // Расшифровываем файл и выводим результат на экран.
                DecryptTestFile(receiverPrivateKey);
            }
        }

        [Fact]
        public void TestFileAgreeCert2001()
        {
            using (var cert = GetGost2001Certificate())
            {
                var senderPrivateKey = cert.PrivateKey as Gost3410CryptoServiceProvider;
                var receiverPublicKey = cert.PublicKey.Key as Gost3410;
                var receiverPrivateKey = cert.PrivateKey as Gost3410CryptoServiceProvider;
                var fileId = "2001_cert";

                CreateTestFile(fileId);
                // Зашифровываем файл на открытом ключе из сертификата.
                EncryptTestFile(receiverPublicKey, senderPrivateKey, fileId);
                // Расшифровываем файл и выводим результат на экран.
                DecryptTestFile(receiverPrivateKey, fileId);
            }
        }

        [Fact]
        public void TestFileAgreeCert2012_256()
        {
            using (var cert = GetGost2012_256Certificate())
            {
                var senderPrivateKey = cert.PrivateKey as Gost3410_2012_256CryptoServiceProvider;
                var receiverPublicKey = cert.PublicKey.Key as Gost3410_2012_256;
                var receiverPrivateKey = cert.PrivateKey as Gost3410_2012_256CryptoServiceProvider;
                var fileId = "2012_256_cert";

                CreateTestFile(fileId);
                // Зашифровываем файл на открытом ключе из сертификата.
                EncryptTestFile(receiverPublicKey, senderPrivateKey, fileId);
                // Расшифровываем файл и выводим результат на экран.
                DecryptTestFile(receiverPrivateKey, fileId);
            }
        }

        [Fact]
        public void TestFileAgreeCert2012_512()
        {
            using (var cert = GetGost2012_512Certificate())
            {
                var senderPrivateKey = cert.PrivateKey as Gost3410_2012_512CryptoServiceProvider;
                var receiverPublicKey = cert.PublicKey.Key as Gost3410_2012_512;
                var receiverPrivateKey = cert.PrivateKey as Gost3410_2012_512CryptoServiceProvider;
                var fileId = "2012_512_cert";

                CreateTestFile(fileId);
                // Зашифровываем файл на открытом ключе из сертификата.
                EncryptTestFile(receiverPublicKey, senderPrivateKey, fileId);
                // Расшифровываем файл и выводим результат на экран.
                DecryptTestFile(receiverPrivateKey, fileId);
            }
        }

        [Fact]
        public void TestAgreeCert2001Verba()
        {
            using (var cert = GetGost2001Certificate())
            {
                var gost = (Gost3410CryptoServiceProvider)cert.PrivateKey;
                var gostRes = (Gost3410CryptoServiceProvider)cert.PrivateKey;

                var gostPk = (Gost3410CryptoServiceProvider)cert.PublicKey.Key;
                var gostResPk = (Gost3410CryptoServiceProvider)cert.PublicKey.Key;

                var symmetric = new Gost28147CryptoServiceProvider();

                gostPk.CipherOid = "1.2.643.2.2.31.1";
                gostResPk.CipherOid = "1.2.643.2.2.31.1";

                var agree = (GostSharedSecretCryptoServiceProvider)gost.CreateAgree(gostResPk.ExportParameters(false));
                byte[] wrappedKeyBytesArray = agree.Wrap(symmetric, GostKeyWrapMethod.CryptoProKeyWrap);

                var agreeRes = (GostSharedSecretCryptoServiceProvider)gostRes.CreateAgree(gostPk.ExportParameters(false));
                var key = agreeRes.Unwrap(wrappedKeyBytesArray, GostKeyWrapMethod.CryptoProKeyWrap);
            }
        }

        [Fact]
        public void TestAgreeCert2012_256Verba()
        {
            using (var cert = GetGost2012_256Certificate())
            {
                var gost = (Gost3410_2012_256CryptoServiceProvider)cert.PrivateKey;
                var gostRes = (Gost3410_2012_256CryptoServiceProvider)cert.PrivateKey;

                var gostPk = (Gost3410_2012_256CryptoServiceProvider)cert.PublicKey.Key;
                var gostResPk = (Gost3410_2012_256CryptoServiceProvider)cert.PublicKey.Key;

                var symmetric = new Gost28147CryptoServiceProvider();

                gostPk.CipherOid = "1.2.643.2.2.31.1";
                gostResPk.CipherOid = "1.2.643.2.2.31.1";

                var agree = (GostSharedSecretCryptoServiceProvider)gost.CreateAgree(gostResPk.ExportParameters(false));
                byte[] wrappedKeyBytesArray = agree.Wrap(symmetric, GostKeyWrapMethod.CryptoProKeyWrap);

                var agreeRes = (GostSharedSecretCryptoServiceProvider)gostRes.CreateAgree(gostPk.ExportParameters(false));
                var key = agreeRes.Unwrap(wrappedKeyBytesArray, GostKeyWrapMethod.CryptoProKeyWrap);
            }
        }

        [Fact]
        public void TestAgreeCert2012_512Verba()
        {
            using (var cert = GetGost2012_512Certificate())
            {
                var gost = (Gost3410_2012_512CryptoServiceProvider)cert.PrivateKey;
                var gostRes = (Gost3410_2012_512CryptoServiceProvider)cert.PrivateKey;

                var gostPk = (Gost3410_2012_512CryptoServiceProvider)cert.PublicKey.Key;
                var gostResPk = (Gost3410_2012_512CryptoServiceProvider)cert.PublicKey.Key;

                var symmetric = new Gost28147CryptoServiceProvider();

                gostPk.CipherOid = "1.2.643.2.2.31.1";
                gostResPk.CipherOid = "1.2.643.2.2.31.1";

                var agree = (GostSharedSecretCryptoServiceProvider)gost.CreateAgree(gostResPk.ExportParameters(false));
                byte[] wrappedKeyBytesArray = agree.Wrap(symmetric, GostKeyWrapMethod.CryptoProKeyWrap);

                var agreeRes = (GostSharedSecretCryptoServiceProvider)gostRes.CreateAgree(gostPk.ExportParameters(false));
                var key = agreeRes.Unwrap(wrappedKeyBytesArray, GostKeyWrapMethod.CryptoProKeyWrap);
            }
        }

        [Fact]
        public void TestAgreeCert200TkZ()
        {
            using (var cert = GetGost2001Certificate())
            {
                var gost = (Gost3410CryptoServiceProvider)cert.PrivateKey;
                var gostRes = (Gost3410CryptoServiceProvider)cert.PrivateKey;

                var gostPk = (Gost3410CryptoServiceProvider)cert.PublicKey.Key;
                var gostResPk = (Gost3410CryptoServiceProvider)cert.PublicKey.Key;

                var symmetric = new Gost28147CryptoServiceProvider();

                gostPk.CipherOid = "1.2.643.7.1.2.5.1.1";
                gostResPk.CipherOid = "1.2.643.7.1.2.5.1.1";

                var agree = (GostSharedSecretCryptoServiceProvider)gost.CreateAgree(gostResPk.ExportParameters(false));
                byte[] wrappedKeyBytesArray = agree.Wrap(symmetric, GostKeyWrapMethod.CryptoProKeyWrap);

                var agreeRes = (GostSharedSecretCryptoServiceProvider)gostRes.CreateAgree(gostPk.ExportParameters(false));
                var key = agreeRes.Unwrap(wrappedKeyBytesArray, GostKeyWrapMethod.CryptoProKeyWrap);
            }
        }

        [Fact]
        public void TestAgreeCert2012_256TkZ()
        {
            using (var cert = GetGost2012_256Certificate())
            {
                var gost = (Gost3410_2012_256CryptoServiceProvider)cert.PrivateKey;
                var gostRes = (Gost3410_2012_256CryptoServiceProvider)cert.PrivateKey;

                var gostPk = (Gost3410_2012_256CryptoServiceProvider)cert.PublicKey.Key;
                var gostResPk = (Gost3410_2012_256CryptoServiceProvider)cert.PublicKey.Key;

                var symmetric = new Gost28147CryptoServiceProvider();

                gostPk.CipherOid = "1.2.643.7.1.2.5.1.1";
                gostResPk.CipherOid = "1.2.643.7.1.2.5.1.1";

                var agree = (GostSharedSecretCryptoServiceProvider)gost.CreateAgree(gostResPk.ExportParameters(false));
                byte[] wrappedKeyBytesArray = agree.Wrap(symmetric, GostKeyWrapMethod.CryptoProKeyWrap);

                var agreeRes = (GostSharedSecretCryptoServiceProvider)gostRes.CreateAgree(gostPk.ExportParameters(false));
                var key = agreeRes.Unwrap(wrappedKeyBytesArray, GostKeyWrapMethod.CryptoProKeyWrap);
            }
        }

        [Fact]
        public void TestAgreeCert2012_512TkZ()
        {
            using (var cert = GetGost2012_512Certificate())
            {
                var gost = (Gost3410_2012_512CryptoServiceProvider)cert.PrivateKey;
                var gostRes = (Gost3410_2012_512CryptoServiceProvider)cert.PrivateKey;

                var gostPk = (Gost3410_2012_512CryptoServiceProvider)cert.PublicKey.Key;
                var gostResPk = (Gost3410_2012_512CryptoServiceProvider)cert.PublicKey.Key;

                var symmetric = new Gost28147CryptoServiceProvider();

                gostPk.CipherOid = "1.2.643.7.1.2.5.1.1";
                gostResPk.CipherOid = "1.2.643.7.1.2.5.1.1";

                var agree = (GostSharedSecretCryptoServiceProvider)gost.CreateAgree(gostResPk.ExportParameters(false));
                byte[] wrappedKeyBytesArray = agree.Wrap(symmetric, GostKeyWrapMethod.CryptoProKeyWrap);

                var agreeRes = (GostSharedSecretCryptoServiceProvider)gostRes.CreateAgree(gostPk.ExportParameters(false));
                var key = agreeRes.Unwrap(wrappedKeyBytesArray, GostKeyWrapMethod.CryptoProKeyWrap);
            }
        }

        // Создание тестового файла для шифрования.
        static void CreateTestFile(string id)
        {
            string name = string.Format(SourceFileName, id);
            using (StreamWriter sw = new StreamWriter(name))
            {
                sw.Write(name);
            }
            Console.WriteLine("Source file is:{0}", name);
        }

        // Шифрование тестового файла.
        static void EncryptTestFile(
            Gost3410 publicKey,
            Gost3410CryptoServiceProvider privateKey,
            string fileId="2001")
        {
            // Создаем симметричный ключ.
            Gost28147 symmetric = Gost28147.Create();

            // Открываем ключ отправителя.
            Gost3410Parameters srcPublicKeyParameters = privateKey.ExportParameters(false);

            // Создаем agree ключ
            GostSharedSecretAlgorithm agree = privateKey.CreateAgree(
                publicKey.ExportParameters(false));

            // Зашифровываем симметричный ключ на agree ключе.
            byte[] WrappedKey = agree.Wrap(symmetric,
                GostKeyWrapMethod.CryptoPro12KeyWrap);

            // Создаем поток шифратора.
            ICryptoTransform transform = symmetric.CreateEncryptor();

            // Создаем зашифрованный файл.
            using (FileStream ofs = new FileStream(string.Format(EncryptedFileName, fileId), FileMode.Create))
            {
                BinaryWriter bw = new BinaryWriter(ofs);

                // Записываем зашифрованный симметричный ключ.
                bw.Write(WrappedKey.Length);
                bw.Write(WrappedKey);

                // Записываем синхропосылку
                bw.Write(symmetric.IV.Length);
                bw.Write(symmetric.IV);

                // Передаем открытый ключ.
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ofs, srcPublicKeyParameters);

                // Создаем поток шифрования для записи в файл.
                using (CryptoStream cs = new CryptoStream(ofs, transform, CryptoStreamMode.Write))
                {
                    byte[] data = new byte[4096];
                    // Открываем входной файл.
                    using (FileStream ifs = new FileStream(string.Format(SourceFileName, fileId), FileMode.Open, FileAccess.Read))
                    {
                        // и переписываем содержимое в выходной поток.
                        int length = ifs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            cs.Write(data, 0, length);
                            length = ifs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        // Расшифрование тестового файла.
        static void DecryptTestFile(Gost3410CryptoServiceProvider privateKey, string fileId = "2001")
        {
            // Открываем зашифрованный файл.
            using (FileStream ifs = new FileStream(string.Format(EncryptedFileName, fileId), FileMode.Open, FileAccess.Read))
            {
                // Читаем зашифрованный симметричный ключ.
                BinaryReader br = new BinaryReader(ifs);
                byte[] cek;
                int cekLength = br.ReadInt32();
                cek = br.ReadBytes(cekLength);

                // Читаем синхропосылку
                byte[] iv;
                int ivLength = br.ReadInt32();
                iv = br.ReadBytes(ivLength);

                // Читаем открытый ключ.
                BinaryFormatter formatter = new BinaryFormatter();
                Gost3410Parameters srcPublicKeyParameters =
                    (Gost3410Parameters)formatter.Deserialize(ifs);

                // Создаем agree ключ
                GostSharedSecretAlgorithm agree = privateKey.CreateAgree(
                    srcPublicKeyParameters);

                // Расшифровываем симметричный ключ на agree
                SymmetricAlgorithm symmetric = agree.Unwrap(cek,
                    GostKeyWrapMethod.CryptoPro12KeyWrap);
                symmetric.IV = iv;

                // Создаем поток разшифрования.
                ICryptoTransform transform = symmetric.CreateDecryptor();

                // Создаем поток разшифрования из файла.
                using (CryptoStream cs = new CryptoStream(ifs, transform, CryptoStreamMode.Read))
                {
                    // Открываем расшифрованный файл
                    using (FileStream ofs = new FileStream(string.Format(DecryptedFileName, fileId), FileMode.Create))
                    {
                        byte[] data = new byte[4096];
                        // и переписываем содержимое в выходной поток.
                        int length = cs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            ofs.Write(data, 0, length);
                            length = cs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        // Шифрование тестового файла.
        static void EncryptTestFile(
            Gost3410_2012_256 publicKey,
            Gost3410_2012_256CryptoServiceProvider privateKey,
            string fileId="2012_256")
        {
            // Создаем симметричный ключ.
            Gost28147 symmetric = Gost28147.Create();

            // Открываем ключ отправителя.
            Gost3410Parameters srcPublicKeyParameters = privateKey.ExportParameters(false);

            // Создаем agree ключ
            GostSharedSecretAlgorithm agree = privateKey.CreateAgree(
                publicKey.ExportParameters(false));

            // Зашифровываем симметричный ключ на agree ключе.
            byte[] WrappedKey = agree.Wrap(symmetric,
                GostKeyWrapMethod.CryptoPro12KeyWrap);

            // Создаем поток шифратора.
            ICryptoTransform transform = symmetric.CreateEncryptor();

            // Создаем зашифрованный файл.
            using (FileStream ofs = new FileStream(string.Format(EncryptedFileName, fileId), FileMode.Create))
            {
                BinaryWriter bw = new BinaryWriter(ofs);

                // Записываем зашифрованный симметричный ключ.
                bw.Write(WrappedKey.Length);
                bw.Write(WrappedKey);

                // Записываем синхропосылку
                bw.Write(symmetric.IV.Length);
                bw.Write(symmetric.IV);

                // Передаем открытый ключ.
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ofs, srcPublicKeyParameters);

                // Создаем поток шифрования для записи в файл.
                using (CryptoStream cs = new CryptoStream(ofs, transform, CryptoStreamMode.Write))
                {
                    byte[] data = new byte[4096];
                    // Открываем входной файл.
                    using (FileStream ifs = new FileStream(string.Format(SourceFileName, fileId), FileMode.Open, FileAccess.Read))
                    {
                        // и переписываем содержимое в выходной поток.
                        int length = ifs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            cs.Write(data, 0, length);
                            length = ifs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        // Расшифрование тестового файла.
        static void DecryptTestFile(Gost3410_2012_256CryptoServiceProvider privateKey, string fileId = "2012_256")
        {
            // Открываем зашифрованный файл.
            using (FileStream ifs = new FileStream(string.Format(EncryptedFileName, fileId), FileMode.Open, FileAccess.Read))
            {
                // Читаем зашифрованный симметричный ключ.
                BinaryReader br = new BinaryReader(ifs);
                byte[] cek;
                int cekLength = br.ReadInt32();
                cek = br.ReadBytes(cekLength);

                // Читаем синхропосылку
                byte[] iv;
                int ivLength = br.ReadInt32();
                iv = br.ReadBytes(ivLength);

                // Читаем открытый ключ.
                BinaryFormatter formatter = new BinaryFormatter();
                Gost3410Parameters srcPublicKeyParameters =
                    (Gost3410Parameters)formatter.Deserialize(ifs);

                // Создаем agree ключ
                GostSharedSecretAlgorithm agree = privateKey.CreateAgree(
                    srcPublicKeyParameters);

                // Расшифровываем симметричный ключ на agree
                SymmetricAlgorithm symmetric = agree.Unwrap(cek,
                    GostKeyWrapMethod.CryptoPro12KeyWrap);
                symmetric.IV = iv;

                // Создаем поток разшифрования.
                ICryptoTransform transform = symmetric.CreateDecryptor();

                // Создаем поток разшифрования из файла.
                using (CryptoStream cs = new CryptoStream(ifs, transform, CryptoStreamMode.Read))
                {
                    // Открываем расшифрованный файл
                    using (FileStream ofs = new FileStream(string.Format(DecryptedFileName, fileId), FileMode.Create))
                    {
                        byte[] data = new byte[4096];
                        // и переписываем содержимое в выходной поток.
                        int length = cs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            ofs.Write(data, 0, length);
                            length = cs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        // Шифрование тестового файла.
        static void EncryptTestFile(
            Gost3410_2012_512 publicKey,
            Gost3410_2012_512CryptoServiceProvider privateKey,
            string fileId = "2012_512")
        {
            // Создаем симметричный ключ.
            Gost28147 symmetric = Gost28147.Create();

            // Открываем ключ отправителя.
            Gost3410Parameters srcPublicKeyParameters = privateKey.ExportParameters(false);

            // Создаем agree ключ
            GostSharedSecretAlgorithm agree = privateKey.CreateAgree(
                publicKey.ExportParameters(false));

            // Зашифровываем симметричный ключ на agree ключе.
            byte[] WrappedKey = agree.Wrap(symmetric,
                GostKeyWrapMethod.CryptoPro12KeyWrap);

            // Создаем поток шифратора.
            ICryptoTransform transform = symmetric.CreateEncryptor();

            // Создаем зашифрованный файл.
            using (FileStream ofs = new FileStream(string.Format(EncryptedFileName, fileId), FileMode.Create))
            {
                BinaryWriter bw = new BinaryWriter(ofs);

                // Записываем зашифрованный симметричный ключ.
                bw.Write(WrappedKey.Length);
                bw.Write(WrappedKey);

                // Записываем синхропосылку
                bw.Write(symmetric.IV.Length);
                bw.Write(symmetric.IV);

                // Передаем открытый ключ.
                BinaryFormatter formatter = new BinaryFormatter();
                formatter.Serialize(ofs, srcPublicKeyParameters);

                // Создаем поток шифрования для записи в файл.
                using (CryptoStream cs = new CryptoStream(ofs, transform, CryptoStreamMode.Write))
                {
                    byte[] data = new byte[4096];
                    // Открываем входной файл.
                    using (FileStream ifs = new FileStream(string.Format(SourceFileName, fileId), FileMode.Open, FileAccess.Read))
                    {
                        // и переписываем содержимое в выходной поток.
                        int length = ifs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            cs.Write(data, 0, length);
                            length = ifs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        // Расшифрование тестового файла.
        static void DecryptTestFile(Gost3410_2012_512CryptoServiceProvider privateKey, string fileId = "2012_512")
        {
            // Открываем зашифрованный файл.
            using (FileStream ifs = new FileStream(string.Format(EncryptedFileName, fileId), FileMode.Open, FileAccess.Read))
            {
                // Читаем зашифрованный симметричный ключ.
                BinaryReader br = new BinaryReader(ifs);
                byte[] cek;
                int cekLength = br.ReadInt32();
                cek = br.ReadBytes(cekLength);

                // Читаем синхропосылку
                byte[] iv;
                int ivLength = br.ReadInt32();
                iv = br.ReadBytes(ivLength);

                // Читаем открытый ключ.
                BinaryFormatter formatter = new BinaryFormatter();
                Gost3410Parameters srcPublicKeyParameters =
                    (Gost3410Parameters)formatter.Deserialize(ifs);

                // Создаем agree ключ
                GostSharedSecretAlgorithm agree = privateKey.CreateAgree(
                    srcPublicKeyParameters);

                // Расшифровываем симметричный ключ на agree
                SymmetricAlgorithm symmetric = agree.Unwrap(cek,
                    GostKeyWrapMethod.CryptoPro12KeyWrap);
                symmetric.IV = iv;

                // Создаем поток разшифрования.
                ICryptoTransform transform = symmetric.CreateDecryptor();

                // Создаем поток разшифрования из файла.
                using (CryptoStream cs = new CryptoStream(ifs, transform, CryptoStreamMode.Read))
                {
                    // Открываем расшифрованный файл
                    using (FileStream ofs = new FileStream(string.Format(DecryptedFileName, fileId), FileMode.Create))
                    {
                        byte[] data = new byte[4096];
                        // и переписываем содержимое в выходной поток.
                        int length = cs.Read(data, 0, data.Length);
                        while (length > 0)
                        {
                            ofs.Write(data, 0, length);
                            length = cs.Read(data, 0, data.Length);
                        }
                    }
                }
            }
        }

        private static Gost3410CryptoServiceProvider GetGostProvider2001()
        {
            CspParameters cpsParams = new CspParameters(
                75,
                "",
                "\\\\.\\HDIMAGE\\G2001256");
            return new Gost3410CryptoServiceProvider(cpsParams);
        }

        private static Gost3410_2012_256CryptoServiceProvider GetGostProvider2012_256()
        {
            CspParameters cpsParams = new CspParameters(
                80,
                "",
                "\\\\.\\HDIMAGE\\G2012256");
            return new Gost3410_2012_256CryptoServiceProvider(cpsParams);
        }

        private static Gost3410_2012_512CryptoServiceProvider GetGostProvider2012_512()
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
