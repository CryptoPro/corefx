namespace System.Security.Cryptography
{
    /// <summary>
    /// Класс восстановления по данным обмена симметричного ключа
    /// на основе <a href="http://www.ietf.org/rfc/rfc4490">ГОСТ Р 34.10 
    /// транспорта</a>.
    /// </summary>
    /// 
    /// <remarks>
    /// <para>Класс позволяет получателю расшифровать данные, которые 
    /// отправителя и использовать их в качестве симметричного ключа для 
    /// расшифрования сообщения.
    /// </para>
    /// <para>Для зашифрования симметричного ключа и формирования данных 
    /// обмена ключами служит класс
    /// <see cref="GostKeyExchangeFormatter"/>.</para>
    /// </remarks>
    /// 
    /// <doc-sample path="Simple\Encrypt" name="KeyExchange">Пример работы с 
    /// форматтером и деформаттером обмена ключами.</doc-sample>
    public class GostKeyExchangeDeformatter : AsymmetricKeyExchangeDeformatter
    {
        /// <summary>
        /// Ассиметричный ключ получателя, на котором зашифрована 
        /// иформация обмена ключами.
        /// </summary>
        private Gost3410 _gostKey;

        /// <summary>
        /// Параметры алгоритма.
        /// </summary>
        /// <value>Всегда <see langword="null"/></value>
        public override string Parameters
        {
            get
            {
                return null;
            }
            set
            {
            }
        }

        /// <summary>
        /// Конструктор объекта класса <see cref="GostKeyExchangeDeformatter"/>
        /// </summary>
        public GostKeyExchangeDeformatter()
        {
        }

        /// <summary>
        /// Конструктор объекта класса <see cref="GostKeyExchangeDeformatter"/> 
        /// с заданным ключом.
        /// </summary>
        /// 
        /// <param name="key">Объект класса 
        /// <see cref="AsymmetricAlgorithm"/>
        /// содержащий секретный ключ для расшифрования данных обмена 
        /// ключами.</param>
        /// 
        /// <argnull name="key" />
        public GostKeyExchangeDeformatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            _gostKey = (Gost3410)key;
        }

        /// <summary>
        /// Восстановления по данным обмена симметричного ключа
        /// на основе <a href="http://www.ietf.org/rfc/rfc4490">ГОСТ Р 34.10 
        /// транспорта</a>.
        /// </summary>
        /// 
        /// <param name="rgb">Данные обмена ключами.</param>
        /// 
        /// <returns>"Чистый" симметричный ключ.</returns>
        /// 
        /// <remarks>
        /// <para>Ключ должен быть определен до вызова метода.</para>
        /// <if notdefined="symimp"><para>В данной сборке функция всегда 
        /// возбуждает исключение <see cref="CryptographicException"/>.
        /// </para></if>
        /// <para>В зависимости от сборки функция может всегда возбуждать 
        /// исключение <see cref="CryptographicException"/>, так
        /// как использует "чистый" ключ. По возможности используйте 
        /// безопасную функцию 
        /// <see cref="DecryptKeyExchange(GostKeyTransport)"/></para>
        /// </remarks>
        /// 
        /// <argnull name="rgb" />
        public override byte[] DecryptKeyExchange(byte[] rgb)
        {
            if (rgb == null)
                throw new ArgumentNullException("rgb");

            SymmetricAlgorithm alg = DecryptKeyExchangeData(rgb);
            return alg.Key;
        }

        /// <summary>
        /// Восстановления по данным обмена симметричного ключа
        /// на основе <a href="http://www.ietf.org/rfc/rfc4490">ГОСТ Р 34.10 
        /// транспорта</a>.
        /// </summary>
        /// 
        /// <param name="transport"> Зашифрованные данные обмена 
        /// ключами.</param>
        /// 
        /// <returns>Симметричный ключ.</returns>
        /// 
        /// <argnull name="transport" />
        public SymmetricAlgorithm DecryptKeyExchange(GostKeyTransport transport)
        {
            GostSharedSecretAlgorithm agree = _gostKey.CreateAgree(
                transport.TransportParameters);

            return agree.Unwrap(transport.SessionEncryptedKey.GetXmlWrappedKey(),
                GostKeyWrapMethod.CryptoProKeyWrap);
        }

        /// <summary>
        /// Восстановления по данным обмена симметричного ключа
        /// на основе <a href="http://www.ietf.org/rfc/rfc4490">ГОСТ Р 34.10 
        /// транспорта</a>.
        /// </summary>
        /// 
        /// <param name="data"> Зашифрованные данные обмена 
        /// ключами.</param>
        /// 
        /// <returns>Симметричный ключ.</returns>
        /// 
        /// <argnull name="data" />
        public SymmetricAlgorithm DecryptKeyExchangeData(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            GostKeyTransport transport = new GostKeyTransport();
            transport.Decode(data);
            return DecryptKeyExchange(transport);
        }

        /// <summary>
        /// Устанавливает секретный ключ.
        /// </summary>
        /// 
        /// <param name="key">Объект класса AsymmetricAlgorithm, 
        /// содержащий секретный ключ.</param>
        /// 
        /// <remarks><para>Ключ должен быть установлен до вызова 
        /// функций восстановления ключа.</para>
        /// </remarks>
        /// 
        /// <argnull name="key" />
        /// <exception cref="CryptographicException">
        /// <paramref name="key"/> не поддерживает алгоритм
        /// <see cref="Gost3410"/>.</exception>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            Gost3410 gost = key as Gost3410;
            if (gost == null)
            {
                throw new CryptographicException(
                   "Parameter must support GOST R 34.10 algorithm");
            }
            _gostKey = gost;
        }
    }
}
