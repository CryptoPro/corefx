namespace System.Security.Cryptography.Encryption.KeyExchange.Tests
{
    using Xunit;
    using System.Security.Cryptography;
    using System.Text;
    using System.Collections;
    using System.IO;
    using System.Runtime.Serialization.Formatters.Binary;

    public class GostSharedSecretTest
    {
        const string SourceFileName = "src_file_{0}.txt";
        const string EncryptedFileName = "end_file_{0}.txt";
        const string DecryptedFileName = "dec_file_{0}.txt";

        [Fact]
        public void TestFileAgree2001()
        {
            var provider = GetGostProvider2001();
            var senderPrivateKey = provider;
            var receiverPublicKey = provider;
            var receiverPrivateKey = provider;

            CreateTestFile("2001");
            // Зашифровываем файл на открытом ключе из сертификата.
            EncryptTestFile(receiverPublicKey, senderPrivateKey);
            // Расшифровываем файл и выводим результат на экран.
            DecryptTestFile(receiverPrivateKey);
        }

        [Fact]
        public void TestFileAgree2012_256()
        {
            var provider = GetGostProvider2012_256();
            var senderPrivateKey = provider;
            var receiverPublicKey = provider;
            var receiverPrivateKey = provider;

            CreateTestFile("2012_256");
            // Зашифровываем файл на открытом ключе из сертификата.
            EncryptTestFile(receiverPublicKey, senderPrivateKey);
            // Расшифровываем файл и выводим результат на экран.
            DecryptTestFile(receiverPrivateKey);
        }

        [Fact]
        public void TestFileAgree2012_512()
        {
            var provider = GetGostProvider2012_512();
            var senderPrivateKey = provider;
            var receiverPublicKey = provider;
            var receiverPrivateKey = provider;

            CreateTestFile("2012_512");
            // Зашифровываем файл на открытом ключе из сертификата.
            EncryptTestFile(receiverPublicKey, senderPrivateKey);
            // Расшифровываем файл и выводим результат на экран.
            DecryptTestFile(receiverPrivateKey);
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
            Gost3410CryptoServiceProvider privateKey)
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
            using (FileStream ofs = new FileStream(string.Format(EncryptedFileName, "2001"), FileMode.Create))
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
                    using (FileStream ifs = new FileStream(string.Format(SourceFileName, "2001"), FileMode.Open, FileAccess.Read))
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
        static void DecryptTestFile(Gost3410CryptoServiceProvider privateKey)
        {
            // Открываем зашифрованный файл.
            using (FileStream ifs = new FileStream(string.Format(EncryptedFileName, "2001"), FileMode.Open, FileAccess.Read))
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
                    using (FileStream ofs = new FileStream(string.Format(DecryptedFileName, "2001"), FileMode.Create))
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
            Gost3410_2012_256CryptoServiceProvider privateKey)
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
            using (FileStream ofs = new FileStream(string.Format(EncryptedFileName, "2012_256"), FileMode.Create))
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
                    using (FileStream ifs = new FileStream(string.Format(SourceFileName, "2012_256"), FileMode.Open, FileAccess.Read))
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
        static void DecryptTestFile(Gost3410_2012_256CryptoServiceProvider privateKey)
        {
            // Открываем зашифрованный файл.
            using (FileStream ifs = new FileStream(string.Format(EncryptedFileName, "2012_256"), FileMode.Open, FileAccess.Read))
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
                    using (FileStream ofs = new FileStream(string.Format(DecryptedFileName, "2012_256"), FileMode.Create))
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
            Gost3410_2012_512CryptoServiceProvider privateKey)
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
            using (FileStream ofs = new FileStream(string.Format(EncryptedFileName, "2012_512"), FileMode.Create))
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
                    using (FileStream ifs = new FileStream(string.Format(SourceFileName, "2012_512"), FileMode.Open, FileAccess.Read))
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
        static void DecryptTestFile(Gost3410_2012_512CryptoServiceProvider privateKey)
        {
            // Открываем зашифрованный файл.
            using (FileStream ifs = new FileStream(string.Format(EncryptedFileName, "2012_512"), FileMode.Open, FileAccess.Read))
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
                    using (FileStream ofs = new FileStream(string.Format(DecryptedFileName, "2012_512"), FileMode.Create))
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
    }
}
