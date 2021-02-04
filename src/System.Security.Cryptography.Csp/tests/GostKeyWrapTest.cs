namespace System.Security.Cryptography.Encryption.KeyExchange.Tests
{
    using Xunit;
    using System.Security.Cryptography;

    public class GostKeyWrapTest
    {
        [Fact]
        public void TestCryptoProKeyWrap()
        {
            TestKeyWrap(GostKeyWrapMethod.CryptoProKeyWrap);
        }

        [Fact]
        public void TestCryptoPro12KeyWrap()
        {
            TestKeyWrap(GostKeyWrapMethod.CryptoPro12KeyWrap);
        }

        [Fact]
        public void TestGostKeyWrap()
        {
            TestKeyWrap(GostKeyWrapMethod.GostKeyWrap);
        }

        private void TestKeyWrap(GostKeyWrapMethod keyWrapMethod)
        {
            using (Gost28147 gost = new Gost28147CryptoServiceProvider())
            {
                using (Gost28147 keyToWrap = new Gost28147CryptoServiceProvider())
                {

                    var data = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1 };
                    var encryptedData = GostEncrypt(keyToWrap, data);

                    var wrappedKey = gost.Wrap(keyToWrap, keyWrapMethod);
                    var unwrappedKey = gost.Unwrap(wrappedKey, keyWrapMethod) as Gost28147;
                    var iv = keyToWrap.IV;

                    var decryptedData = GostDecrypt(unwrappedKey, encryptedData, iv);

                    Assert.Equal(data, decryptedData);
                }
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
        byte[] GostDecrypt(Gost28147 key, byte[] encBytes, byte[] IV)
        {
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
    }
}
