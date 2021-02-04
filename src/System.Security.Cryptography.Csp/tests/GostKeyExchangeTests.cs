namespace System.Security.Cryptography.Encryption.KeyExchange.Tests
{
    using Xunit;
    using System.Security.Cryptography;
    using System.Text;
    using System.Collections;
    using System.Security.Cryptography.X509Certificates;

    public class GostKeyExchange
    {
        [Fact]
        public void TestKeyExchange2001()
        {
            // Ассиметричный ключ получателя.
            Gost3410 AssymKey;
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            using (Gost3410 gkey = GetGostProvider2001())
            {
                AssymKey = gkey;

                // Создаем случайный секретный ключ, который необходимо передать.
                Gost28147 key = new Gost28147CryptoServiceProvider();
                // Синхропосылка не входит в GostKeyTransport и должна
                // передаваться отдельно.
                IV = key.IV;

                // Создаем форматтер, шифрующий на ассиметричном ключе получателя.
                GostKeyExchangeFormatter Formatter = new GostKeyExchangeFormatter(AssymKey);
                // GostKeyTransport - формат зашифрованной для безопасной передачи 
                // ключевой информации.
                GostKeyTransport encKey = Formatter.CreateKeyExchange(key);

                // Шифруемая строка
                string message = "012345678901234567890";
                byte[] sourceBytes = Encoding.ASCII.GetBytes(message);
                Console.WriteLine("** Строка до шифрования: " + message);

                // Шифруем строку на сессионном ключе
                byte[] encBytes = GostEncrypt(key, sourceBytes);
                Console.WriteLine("** Строка после шифрования: " +
                       Encoding.ASCII.GetString(encBytes));

                // Получатель расшифровывает GostKeyTransport и само сообщение.
                byte[] decBytes = GostDecrypt(encKey, encBytes, IV, AssymKey);
                Console.WriteLine("** Строка после расшифрования: " +
                      Encoding.ASCII.GetString(decBytes));

                Assert.Equal(sourceBytes, decBytes);
            }
        }

        [Fact]
        public void TestKeyExchange2012_256()
        {
            // Ассиметричный ключ получателя.
            Gost3410_2012_256 AssymKey;
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            using (Gost3410_2012_256 gkey = GetGostProvider2012_256())
            {
                AssymKey = gkey;

                // Создаем случайный секретный ключ, который необходимо передать.
                Gost28147 key = new Gost28147CryptoServiceProvider();
                // Синхропосылка не входит в GostKeyTransport и должна
                // передаваться отдельно.
                IV = key.IV;

                // Создаем форматтер, шифрующий на ассиметричном ключе получателя.
                GostKeyExchangeFormatter Formatter = new GostKeyExchangeFormatter(AssymKey);
                // GostKeyTransport - формат зашифрованной для безопасной передачи 
                // ключевой информации.
                GostKeyTransport encKey = Formatter.CreateKeyExchange(key);

                // Шифруемая строка
                string message = "012345678901234567890";
                byte[] sourceBytes = Encoding.ASCII.GetBytes(message);
                Console.WriteLine("** Строка до шифрования: " + message);

                // Шифруем строку на сессионном ключе
                byte[] encBytes = GostEncrypt(key, sourceBytes);
                Console.WriteLine("** Строка после шифрования: " +
                       Encoding.ASCII.GetString(encBytes));

                // Получатель расшифровывает GostKeyTransport и само сообщение.
                byte[] decBytes = GostDecrypt(encKey, encBytes, IV, AssymKey);
                Console.WriteLine("** Строка после расшифрования: " +
                      Encoding.ASCII.GetString(decBytes));

                Assert.Equal(sourceBytes, decBytes);
            }
        }

        [Fact]
        public void TestKeyExchange2012_512()
        {
            // Ассиметричный ключ получателя.
            Gost3410_2012_512 AssymKey;
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            using (Gost3410_2012_512 gkey = GetGostProvider2012_512())
            {
                AssymKey = gkey;

                // Создаем случайный секретный ключ, который необходимо передать.
                Gost28147 key = new Gost28147CryptoServiceProvider();
                // Синхропосылка не входит в GostKeyTransport и должна
                // передаваться отдельно.
                IV = key.IV;

                // Создаем форматтер, шифрующий на ассиметричном ключе получателя.
                GostKeyExchangeFormatter Formatter = new GostKeyExchangeFormatter(AssymKey);
                // GostKeyTransport - формат зашифрованной для безопасной передачи 
                // ключевой информации.
                GostKeyTransport encKey = Formatter.CreateKeyExchange(key);

                // Шифруемая строка
                string message = "012345678901234567890";
                byte[] sourceBytes = Encoding.ASCII.GetBytes(message);
                Console.WriteLine("** Строка до шифрования: " + message);

                // Шифруем строку на сессионном ключе
                byte[] encBytes = GostEncrypt(key, sourceBytes);
                Console.WriteLine("** Строка после шифрования: " +
                       Encoding.ASCII.GetString(encBytes));

                // Получатель расшифровывает GostKeyTransport и само сообщение.
                byte[] decBytes = GostDecrypt(encKey, encBytes, IV, AssymKey);
                Console.WriteLine("** Строка после расшифрования: " +
                      Encoding.ASCII.GetString(decBytes));

                Assert.Equal(sourceBytes, decBytes);
            }
        }

        [Fact]
        public void TestKeyExchangeCert2001()
        {
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            using (var cert = GetGost2001Certificate())
            {
                // Создаем случайный секретный ключ, который необходимо передать.
                Gost28147 key = new Gost28147CryptoServiceProvider();
                // Синхропосылка не входит в GostKeyTransport и должна
                // передаваться отдельно.
                IV = key.IV;

                // Создаем форматтер, шифрующий на ассиметричном ключе получателя.
                GostKeyExchangeFormatter Formatter = new GostKeyExchangeFormatter(cert.PublicKey.Key as Gost3410);
                // GostKeyTransport - формат зашифрованной для безопасной передачи 
                // ключевой информации.
                GostKeyTransport encKey = Formatter.CreateKeyExchange(key);

                // Шифруемая строка
                string message = "012345678901234567890";
                byte[] sourceBytes = Encoding.ASCII.GetBytes(message);
                Console.WriteLine("** Строка до шифрования: " + message);

                // Шифруем строку на сессионном ключе
                byte[] encBytes = GostEncrypt(key, sourceBytes);
                Console.WriteLine("** Строка после шифрования: " +
                       Encoding.ASCII.GetString(encBytes));

                // Получатель расшифровывает GostKeyTransport и само сообщение.
                byte[] decBytes = GostDecrypt(encKey, encBytes, IV, cert.PrivateKey);
                Console.WriteLine("** Строка после расшифрования: " +
                      Encoding.ASCII.GetString(decBytes));

                Assert.Equal(sourceBytes, decBytes);
            }
        }

        [Fact]
        public void TestKeyExchangeCert2012_256()
        {
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            using (var cert = GetGost2012_256Certificate())
            {
                // Создаем случайный секретный ключ, который необходимо передать.
                Gost28147 key = new Gost28147CryptoServiceProvider();
                // Синхропосылка не входит в GostKeyTransport и должна
                // передаваться отдельно.
                IV = key.IV;

                // Создаем форматтер, шифрующий на ассиметричном ключе получателя.
                GostKeyExchangeFormatter Formatter = new GostKeyExchangeFormatter(cert.PublicKey.Key as Gost3410_2012_256);
                // GostKeyTransport - формат зашифрованной для безопасной передачи 
                // ключевой информации.
                GostKeyTransport encKey = Formatter.CreateKeyExchange(key);

                // Шифруемая строка
                string message = "012345678901234567890";
                byte[] sourceBytes = Encoding.ASCII.GetBytes(message);
                Console.WriteLine("** Строка до шифрования: " + message);

                // Шифруем строку на сессионном ключе
                byte[] encBytes = GostEncrypt(key, sourceBytes);
                Console.WriteLine("** Строка после шифрования: " +
                       Encoding.ASCII.GetString(encBytes));

                // Получатель расшифровывает GostKeyTransport и само сообщение.
                byte[] decBytes = GostDecrypt(encKey, encBytes, IV, cert.PrivateKey);
                Console.WriteLine("** Строка после расшифрования: " +
                      Encoding.ASCII.GetString(decBytes));

                Assert.Equal(sourceBytes, decBytes);
            }
        }

        [Fact]
        public void TestKeyExchangeCert2012_512()
        {
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            using (var cert = GetGost2012_512Certificate())
            {
                // Создаем случайный секретный ключ, который необходимо передать.
                Gost28147 key = new Gost28147CryptoServiceProvider();
                // Синхропосылка не входит в GostKeyTransport и должна
                // передаваться отдельно.
                IV = key.IV;

                // Создаем форматтер, шифрующий на ассиметричном ключе получателя.
                GostKeyExchangeFormatter Formatter = new GostKeyExchangeFormatter(cert.PublicKey.Key as Gost3410_2012_512);
                // GostKeyTransport - формат зашифрованной для безопасной передачи 
                // ключевой информации.
                GostKeyTransport encKey = Formatter.CreateKeyExchange(key);

                // Шифруемая строка
                string message = "012345678901234567890";
                byte[] sourceBytes = Encoding.ASCII.GetBytes(message);
                Console.WriteLine("** Строка до шифрования: " + message);

                // Шифруем строку на сессионном ключе
                byte[] encBytes = GostEncrypt(key, sourceBytes);
                Console.WriteLine("** Строка после шифрования: " +
                       Encoding.ASCII.GetString(encBytes));

                // Получатель расшифровывает GostKeyTransport и само сообщение.
                byte[] decBytes = GostDecrypt(encKey, encBytes, IV, cert.PrivateKey);
                Console.WriteLine("** Строка после расшифрования: " +
                      Encoding.ASCII.GetString(decBytes));

                Assert.Equal(sourceBytes, decBytes);
            }
        }

        // Шифруем байтовый массив
        byte[] GostEncrypt(Gost28147 key, byte[] sourceBytes)
        {
            int currentPosition = 0;
            byte[] targetBytes = new byte[1024];
            int sourceByteLength = sourceBytes.Length;

            // Создаем шифратор для ГОСТ.
            ICryptoTransform cryptoTransform = key.CreateEncryptor();

            // Размер блока считанных байт.
            int inputBlockSize = cryptoTransform.InputBlockSize;

            // Размер выходного блока.
            int outputBlockSize = cryptoTransform.OutputBlockSize;

            try
            {
                // Если возможна обработка нескольких блоков:
                if (cryptoTransform.CanTransformMultipleBlocks)
                {
                    int numBytesRead = 0;
                    while (sourceByteLength - currentPosition >= inputBlockSize)
                    {
                        // Преобразуем байты начиная с currentPosition в массиве 
                        // sourceBytes, записывая результат в массив targetBytes.
                        numBytesRead = cryptoTransform.TransformBlock(
                        sourceBytes, currentPosition,
                        inputBlockSize, targetBytes,
                            currentPosition);
                        currentPosition += numBytesRead;
                    }
                    // Преобразуем последний блок.
                    byte[] finalBytes = cryptoTransform.TransformFinalBlock(
                        sourceBytes, currentPosition,
                        sourceByteLength - currentPosition);

                    // Записываем последний зашифрованный блок 
                    // в массив targetBytes.
                    finalBytes.CopyTo(targetBytes, currentPosition);

                    currentPosition += finalBytes.Length;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught unexpected exception:" + ex.ToString());
            }
            // Определяем, может ли CPCryptoAPITransform использоваться повторно.
            if (!cryptoTransform.CanReuseTransform)
            {
                // Освобождаем занятые ресурсы.
                cryptoTransform.Dispose();
            }
            // Убираем неиспользуемые байты из массива.
            return TrimArray(targetBytes, currentPosition);
        }

        // Действия получателя - расшифровываем полученные сессионный ключ и сообщение.
        byte[] GostDecrypt(GostKeyTransport encKey, byte[] encBytes, byte[] IV, AsymmetricAlgorithm AssymKey)
        {
            // Деформаттер для ключей, зашифрованных на ассиметричном ключе получателя.
            GostKeyExchangeDeformatter Deformatter = new GostKeyExchangeDeformatter(AssymKey);
            // Получаем ГОСТ-овый ключ из GostKeyTransport.
            Gost28147 key = (Gost28147)Deformatter.DecryptKeyExchange(encKey);
            // Устанавливаем синхропосылку.
            key.IV = IV;
            byte[] targetBytes = new byte[1024];
            int currentPosition = 0;

            // Создаем дешифратор для ГОСТ.
            ICryptoTransform cryptoTransform =
                key.CreateDecryptor();

            int inputBlockSize = cryptoTransform.InputBlockSize;
            int sourceByteLength = encBytes.Length;

            try
            {
                int numBytesRead = 0;
                while (sourceByteLength - currentPosition >= inputBlockSize)
                {
                    // Преобразуем байты начиная с currentPosition в массиве 
                    // sourceBytes, записывая результат в массив targetBytes.
                    numBytesRead = cryptoTransform.TransformBlock(
                        encBytes,
                        currentPosition,
                        inputBlockSize,
                        targetBytes,
                        currentPosition);

                    currentPosition += numBytesRead;
                }

                // Преобразуем последний блок.
                byte[] finalBytes = cryptoTransform.TransformFinalBlock(
                    encBytes,
                    currentPosition,
                    sourceByteLength - currentPosition);

                // Записываем последний расшифрованный блок 
                // в массив targetBytes.
                finalBytes.CopyTo(targetBytes, currentPosition);

                currentPosition += finalBytes.Length;
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught unexpected exception:" + ex.ToString());
            }
            // Убираем неиспользуемые байты из массива.
            return TrimArray(targetBytes, currentPosition);
        }
        private static byte[] TrimArray(byte[] targetArray, int count)
        {
            // Создаем новый массив нужного размера.
            byte[] returnedArray = new byte[count];
            for (int j = 0; j < count; j++)
            {
                returnedArray[j] = targetArray[j];
            }
            return returnedArray;
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
