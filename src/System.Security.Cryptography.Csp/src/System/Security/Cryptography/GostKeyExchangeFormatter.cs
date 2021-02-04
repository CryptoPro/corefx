using static Internal.NativeCrypto.CapiHelper;

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
        private AsymmetricAlgorithm _gostKey;

        /// <summary>
        /// Тип алгоритма ключа
        /// </summary>
        private CspAlgorithmType _gostAlgorithmType;

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
            SetKey(key);
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
        /// <see cref="CreateKeyExchange(SymmetricAlgorithm, GostKeyWrapMethod)"/></para>
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
        /// <see cref="CreateKeyExchange(SymmetricAlgorithm, GostKeyWrapMethod)"/></para>
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
        /// <param name="keyWrapMethod">Алгоритм симметричного экспорта</param>
        /// 
        /// <returns>Зашифрованные данные для отправки стороне 
        /// получателю.</returns>
        /// 
        /// <argnull name="alg" />
        public GostKeyTransport CreateKeyExchange(
            SymmetricAlgorithm alg, 
            GostKeyWrapMethod keyWrapMethod = GostKeyWrapMethod.CryptoPro12KeyWrap)
        {
            if (alg == null)
                throw new ArgumentNullException("alg");

            // Получаем параметры получателя.
            Gost3410Parameters senderParameters;
            switch (_gostAlgorithmType)
            {
                case CspAlgorithmType.Gost2001:
                {
                    senderParameters = ((Gost3410)_gostKey).ExportParameters(false);
                    using (Gost3410EphemeralCryptoServiceProvider sender =
                        new Gost3410EphemeralCryptoServiceProvider(senderParameters))
                    {
                        return GetGostTransport(
                            sender.CreateAgree,
                            sender.ExportParameters,
                            senderParameters,
                            alg,
                            keyWrapMethod);

                    }
                }
                case CspAlgorithmType.Gost2012_256:
                {
                    senderParameters = ((Gost3410_2012_256)_gostKey).ExportParameters(false);
                    using (Gost3410_2012_256EphemeralCryptoServiceProvider sender =
                        new Gost3410_2012_256EphemeralCryptoServiceProvider(senderParameters))
                    {
                        return GetGostTransport(
                            sender.CreateAgree,
                            sender.ExportParameters,
                            senderParameters,
                            alg,
                            keyWrapMethod);

                    }
                }
                case CspAlgorithmType.Gost2012_512:
                {
                    senderParameters = ((Gost3410_2012_512)_gostKey).ExportParameters(false);
                    using (Gost3410_2012_512EphemeralCryptoServiceProvider sender =
                        new Gost3410_2012_512EphemeralCryptoServiceProvider(senderParameters))
                    {
                        return GetGostTransport(
                            sender.CreateAgree,
                            sender.ExportParameters,
                            senderParameters,
                            alg,
                            keyWrapMethod);

                    }
                }
                default:
                {
                    throw new NotSupportedException();
                }
            }
        }

        /// <summary>
        /// Вспомогательный метод, работающий для всех GOST3410
        /// </summary>
        /// <param name="createAgree"></param>
        /// <param name="exportParameters"></param>
        /// <param name="senderParameters"></param>
        /// <param name="alg"></param>
        /// <param name="keyWrapMethod"></param>
        /// <returns></returns>
        private GostKeyTransport GetGostTransport(
        Func<Gost3410Parameters, GostSharedSecretAlgorithm> createAgree,
        Func<bool, Gost3410Parameters> exportParameters,
        Gost3410Parameters senderParameters,
        SymmetricAlgorithm alg,
        GostKeyWrapMethod keyWrapMethod)
        {
            GostKeyTransportObject transport = new GostKeyTransportObject();
            byte[] wrapped_data;

            using (GostSharedSecretAlgorithm agree = createAgree(
                    senderParameters))
            {
                // Зашифровываем симметричный ключ.
                wrapped_data = agree.Wrap(alg,
                    keyWrapMethod);
            }

            GostWrappedKeyObject wrapped = new GostWrappedKeyObject();
            wrapped.SetByXmlWrappedKey(wrapped_data);

            transport.sessionEncryptedKey_ = wrapped;
            transport.transportParameters_ = new Gost3410CspObject();
            transport.transportParameters_.Parameters = exportParameters(false);

            return transport.Transport;
        }

        /// <summary>
        /// Формирование данных обмена, на основе симметричного
        /// ключа шифрования сообщения ГОСТ 28147.
        /// </summary>
        /// 
        /// <param name="alg">Симметричный ключ ГОСТ 28147.</param>
        /// <param name="wrapMethod">Алгоритм экспорта</param>
        /// <returns>Зашифрованные данные для отправки стороне 
        /// получателю.</returns>
        /// 
        /// <argnull name="alg" />
        public byte[] CreateKeyExchangeData(SymmetricAlgorithm alg, GostKeyWrapMethod wrapMethod = GostKeyWrapMethod.CryptoPro12KeyWrap)
        {
            GostKeyTransport transport = CreateKeyExchange(alg, wrapMethod);
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
                throw new ArgumentNullException(nameof(key));

            if (key is Gost3410 gost3410)
            {
                _gostAlgorithmType = CspAlgorithmType.Gost2001;
                _gostKey = gost3410;
            }
            else if (key is Gost3410_2012_256 gost3410_2012_256)
            {
                _gostAlgorithmType = CspAlgorithmType.Gost2012_256;
                _gostKey = gost3410_2012_256;
            }
            else if (key is Gost3410_2012_512 gost3410_2012_512)
            {
                _gostAlgorithmType = CspAlgorithmType.Gost2012_512;
                _gostKey = gost3410_2012_512;
            }
            else
            {
                throw new NotSupportedException();
            }
        }
    }
}
