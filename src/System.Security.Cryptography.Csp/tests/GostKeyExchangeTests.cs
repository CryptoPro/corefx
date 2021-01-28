namespace System.Security.Cryptography.Encryption.KeyExchange.Tests
{
    using Xunit;
    using System.Security.Cryptography;
    using System.Text;
    using System.Collections;

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
            Gost3410 gkey = GetGostProvider2001();
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

        [Fact]
        public void TestKeyExchange2012_256()
        {
            // Ассиметричный ключ получателя.
            Gost3410_2012_256 AssymKey;
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            Gost3410_2012_256 gkey = GetGostProvider2012_256();
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

        [Fact]
        public void TestKeyExchange2012_512()
        {
            // Ассиметричный ключ получателя.
            Gost3410_2012_512 AssymKey;
            // Синхропосылка.
            byte[] IV;

            // Создаем случайный открытый ключ.
            Gost3410_2012_512 gkey = GetGostProvider2012_512();
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
            return TrimArray(targetBytes);
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
            }
            catch (Exception ex)
            {
                Console.WriteLine("Caught unexpected exception:" + ex.ToString());
            }
            // Убираем неиспользуемые байты из массива.
            return TrimArray(targetBytes);
        }
        private static byte[] TrimArray(byte[] targetArray)
        {
            IEnumerator enum1 = targetArray.GetEnumerator();
            int i = 0;
            while (enum1.MoveNext())
            {
                if (enum1.Current.ToString().Equals("0"))
                {
                    break;
                }
                i++;
            }
            // Создаем новый массив нужного размера.
            byte[] returnedArray = new byte[i];
            for (int j = 0; j < i; j++)
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
    }
}
