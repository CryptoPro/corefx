namespace System.Security.Cryptography
{
    /// <summary>
    /// Абстрактный базовый класс для всех реализаций ключа согласования.
    /// </summary>
    /// 
    /// <remarks>
    /// Ключ согласования используется для шифрования/расшифрования 
    /// симметричных ключей.
    /// </remarks>
    /// 
    /// <doc-sample path="Simple\Encrypt" name="gEncryptFileAgree">Пример использования
    /// agree ключа.</doc-sample>
    public abstract class GostSharedSecretAlgorithm : IDisposable
    {
        /// <summary>
        /// Шифрует секретный ключ.
        /// </summary>
        /// 
        /// <param name="alg">Объект класса <see cref="SymmetricAlgorithm"/>, 
        /// содержащий секретный ключ. </param>
        /// <param name="method">Метод зашифрования ключа.</param>
        /// 
        /// <returns>Зашифрованный ключ.</returns>
        public abstract byte[] Wrap(SymmetricAlgorithm alg,
            GostKeyWrapMethod method);

        /// <summary>
        /// Расшифровывает секретный ключ.
        /// </summary>
        /// 
        /// <param name="wrapped">Зашифрованный ключ.</param>
        /// <param name="method">Метод зашифрования ключа.</param>
        /// 
        /// <returns>Объкт класса <see cref="SymmetricAlgorithm"/>, содержащий 
        /// секретный ключ.</returns>
        public abstract SymmetricAlgorithm Unwrap(byte[] wrapped,
            GostKeyWrapMethod method);

        /// <summary>
        /// Освобождение ресурсов занятых класом.
        /// </summary>
        /// 
        /// <param name="disposing">Вызов из finalize.</param>
        protected virtual void Dispose(bool disposing)
        {
        }

        /// <summary>
        /// Освобождение занятых ресурсов.
        /// </summary>
        public void Dispose()
        {
            this.Dispose(true);
            GC.SuppressFinalize(this);
        }
    }
}
