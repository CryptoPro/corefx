// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.


namespace System.Security.Cryptography.Encryption.TransportArgee.Tests
{
    using Xunit;
    using System.Security.Cryptography;
    using System.Text;
    using System.Collections;

    /// <summary>
    /// Since SHAxCryptoServiceProvider types wraps IncrementalHash from Algorithms assembly, we only test minimally here.
    /// </summary>
    public class KeyExchange
    {
        // Ассиметричный ключ получателя.
        private Gost3410 AssymKey;
        // Синхропосылка.
        private byte[] IV;

        [Fact]
        public void TestKeyExchange()
        {
            // Создаем случайный открытый ключ.
            KeyExchange GostKeyExchange = new KeyExchange();
            Gost3410 gkey = GetGostProvider();
            GostKeyExchange.InitializeKey(gkey);

            // Создаем случайный секретный ключ, который необходимо передать.
            Gost28147 key = new Gost28147CryptoServiceProvider();
            // Синхропосылка не входит в GostKeyTransport и должна
            // передаваться отдельно.
            GostKeyExchange.IV = key.IV;

            // Создаем форматтер, шифрующий на ассиметричном ключе получателя.
            GostKeyExchangeFormatter Formatter = new GostKeyExchangeFormatter(GostKeyExchange.AssymKey);
            // GostKeyTransport - формат зашифрованной для безопасной передачи 
            // ключевой информации.
            GostKeyTransport encKey = Formatter.CreateKeyExchange(key);

            // Шифруемая строка
            string message = "012345678901234567890";
            byte[] sourceBytes = Encoding.ASCII.GetBytes(message);
            Console.WriteLine("** Строка до шифрования: " + message);

            // Шифруем строку на сессионном ключе
            byte[] encBytes = GostKeyExchange.GostEncrypt(key, sourceBytes);
            Console.WriteLine("** Строка после шифрования: " +
                   Encoding.ASCII.GetString(encBytes));

            // Получатель расшифровывает GostKeyTransport и само сообщение.
            byte[] decBytes = GostKeyExchange.GostDecrypt(encKey, encBytes);
            Console.WriteLine("** Строка после расшифрования: " +
                  Encoding.ASCII.GetString(decBytes));

            Console.ReadLine();
        }

        // Создаем ключ получателя.
        private void InitializeKey(Gost3410 gkey)
        {
            AssymKey = gkey;
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
        byte[] GostDecrypt(GostKeyTransport encKey, byte[] encBytes)
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

        private static Gost3410CryptoServiceProvider GetGostProvider()
        {
            CspParameters cpsParams = new CspParameters(
                75,
                "",
                "\\\\.\\HDIMAGE\\G2012256");
            return new Gost3410CryptoServiceProvider(cpsParams);
        }
    }
}
