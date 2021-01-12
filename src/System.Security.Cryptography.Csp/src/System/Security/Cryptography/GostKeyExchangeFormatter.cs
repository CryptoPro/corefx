namespace System.Security.Cryptography
{
    /// <summary>
    /// Класс формирования данных для обмена симметричным ключом
    /// на основе <a href="http://www.ietf.org/rfc/rfc4490">ГОСТ Р 34.10 
    /// транспорта</a>.
    /// </summary>
    /// 
    /// <remarks>
    /// <para>Класс позволяет отправителю сформировать зашифрованные 
    /// данные, которые получатель может расшифровать и использовать
    /// в качестве симметричного ключа для расшифрования сообщения.
    /// </para>
    /// <para>В отличии от аналогичных классов, порожденных от 
    /// <see cref="AsymmetricKeyExchangeFormatter"/>, данный класс
    /// нельзя использовать для получения произвольной общей информации,
    /// или произвольных симметричных ключей. Алгоритм предназначен
    /// <b>только</b> для форматирования данных на основе симметричного 
    /// ключа ГОСТ 28147.
    /// </para>
    /// <para>Для получения данных обмена ключами и извлечения 
    /// соответствующего симметричного ключа служит класс
    /// <see cref="GostKeyExchangeDeformatter"/>.</para>
    /// </remarks>
    /// 
    /// <doc-sample path="Simple\Encrypt" name="KeyExchange">Пример работы с 
    /// форматтером и деформаттером обмена ключами.</doc-sample>
    /// <seealso cref="GostKeyExchangeDeformatter"/>
    public class GostKeyExchangeFormatter : AsymmetricKeyExchangeFormatter
    {
        /// <summary>
        /// Ассиметричный ключ получателя.
        /// </summary>
        private Gost3410 gostKey_;

        /// <summary>
        /// Возвращает параметры обмена ключами.
        /// </summary>
        /// 
        /// <value>Всегда null.</value>
        /// 
        /// <remarks><para>Не используется.</para></remarks>
        public override string Parameters
        {
            get
            {
                return null;
            }
        }

        /// <summary>
        /// Создание объекта класса <see cref="GostKeyExchangeFormatter"/>.
        /// </summary>
        public GostKeyExchangeFormatter()
        {
        }

        /// <summary>
        /// Конструктор объекта класса <see cref="GostKeyExchangeFormatter"/> 
        /// с заданным открытым ключом получателя.
        /// </summary>
        /// 
        /// <param name="key">Класс, содержащий ключ, для которого 
        /// будет производиться шифрование пердаваемой информации.</param>
        /// 
        /// <argnull name="key" />
        public GostKeyExchangeFormatter(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            gostKey_ = (Gost3410)key;
        }

        /// <summary>
        /// Формирование данных обмена, на основе симметричного
        /// ключа шифрования сообщения ГОСТ 28147.
        /// </summary>
        /// 
        /// <param name="data">"Чистый" симметричный ключ 
        /// ГОСТ 28147.</param>
        /// 
        /// <returns>Зашифрованные данные для отправки стороне 
        /// получателю.</returns>
        /// 
        /// <remarks>
        /// <if notdefined="symimp"><para>В данной сборке функция всегда 
        /// возбуждает исключение <see cref="CryptographicException"/>.
        /// </para></if>
        /// <para>В зависимости от сборки функция может всегда возбуждать 
        /// исключение <see cref="CryptographicException"/>, так
        /// как использует "чистый" ключ. По возможности используйте 
        /// безопасную функцию 
        /// <see cref="CreateKeyExchange(SymmetricAlgorithm)"/></para>
        /// </remarks>
        public override byte[] CreateKeyExchange(byte[] data)
        {
            using (Gost28147CryptoServiceProvider alg =
                new Gost28147CryptoServiceProvider())
            {
                alg.Key = data;
                return CreateKeyExchangeData(alg);
            }
        }

        /// <summary>
        /// Формирование данных обмена, на основе симметричного
        /// ключа шифрования сообщения ГОСТ 28147.
        /// </summary>
        /// 
        /// <param name="data">"Чистый" симметричный ключ 
        /// ГОСТ 28147.</param>
        /// <param name="symAlgType">Параметр не используется в
        /// этой версии.</param>
        /// 
        /// <returns>Зашифрованные данные для отправки стороне 
        /// получателю.</returns>
        /// 
        /// <remarks>
        /// <if notdefined="symimp"><para>В данной сборке функция всегда 
        /// возбуждает исключение <see cref="CryptographicException"/>.
        /// </para></if>
        /// <para>В зависимости от сборки функция может всегда возбуждать 
        /// исключение <see cref="CryptographicException"/>, так
        /// как использует "чистый" ключ. По возможности используйте 
        /// безопасную функцию 
        /// <see cref="CreateKeyExchange(SymmetricAlgorithm)"/></para>
        /// </remarks>
        public override byte[] CreateKeyExchange(byte[] data, Type symAlgType)
        {
            return CreateKeyExchange(data);
        }

        /// <summary>
        /// Формирование данных обмена, на основе симметричного
        /// ключа шифрования сообщения ГОСТ 28147.
        /// </summary>
        /// 
        /// <param name="alg">Симметричный ключ ГОСТ 28147.</param>
        /// 
        /// <returns>Зашифрованные данные для отправки стороне 
        /// получателю.</returns>
        /// 
        /// <argnull name="alg" />
        public GostKeyTransport CreateKeyExchange(SymmetricAlgorithm alg)
        {
            if (alg == null)
                throw new ArgumentNullException("alg");

            // Получаем параметры получателя.
            Gost3410Parameters senderParameters = gostKey_.ExportParameters(
                false);

            GostKeyTransportObject transport = new GostKeyTransportObject();

            // Создаем эфимерный ключ с параметрами получателя.
            using (Gost3410EphemeralCryptoServiceProvider sender = new Gost3410EphemeralCryptoServiceProvider(
                senderParameters))
            {
                // Создаем распределенный секрет.
                byte[] wrapped_data;
                using (GostSharedSecretAlgorithm agree = sender.CreateAgree(
                    senderParameters))
                {

                    // Зашифровываем симметричный ключ.
                    wrapped_data = agree.Wrap(alg,
                        GostKeyWrapMethod.CryptoProKeyWrap);
                }

                GostWrappedKeyObject wrapped = new GostWrappedKeyObject();
                wrapped.SetByXmlWrappedKey(wrapped_data);

                transport.sessionEncryptedKey_ = wrapped;
                transport.transportParameters_ = new Gost3410CspObject();
                transport.transportParameters_.Parameters = sender.ExportParameters(false);
            }

            return transport.Transport;
        }

        /// <summary>
        /// Формирование данных обмена, на основе симметричного
        /// ключа шифрования сообщения ГОСТ 28147.
        /// </summary>
        /// 
        /// <param name="alg">Симметричный ключ ГОСТ 28147.</param>
        /// 
        /// <returns>Зашифрованные данные для отправки стороне 
        /// получателю.</returns>
        /// 
        /// <argnull name="alg" />
        public byte[] CreateKeyExchangeData(SymmetricAlgorithm alg)
        {
            GostKeyTransport transport = CreateKeyExchange(alg);
            return transport.Encode();
        }

        /// <summary>
        /// Устанавливает открытый ключ.
        /// </summary>
        /// 
        /// <param name="key">Алгоритм, содержащий открытый ключ 
        /// получателя.</param>
        /// 
        /// <remarks><para>
        /// Данный ключ необходимо установить до первого вызова фунций
        /// формирования обмена данных.</para></remarks>
        public override void SetKey(AsymmetricAlgorithm key)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            gostKey_ = (Gost3410)key;
        }
    }

}
