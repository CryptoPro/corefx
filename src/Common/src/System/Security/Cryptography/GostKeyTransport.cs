using System.Runtime.InteropServices;

namespace System.Security.Cryptography
{
    internal class GostKeyTransportObject
    {
        internal Gost3410CspObject transportParameters_;
        internal GostWrappedKeyObject sessionEncryptedKey_;

        public GostKeyTransport Transport
        {
            get
            {
                GostKeyTransport ret = new GostKeyTransport();
                ret.TransportParameters = transportParameters_.Parameters;
                ret.SessionEncryptedKey = sessionEncryptedKey_.WrappedKey;
                return ret;
            }
            set
            {
                transportParameters_ = new Gost3410CspObject(value.TransportParameters);
                sessionEncryptedKey_ = new GostWrappedKeyObject();
                sessionEncryptedKey_.WrappedKey = value.SessionEncryptedKey;
            }
        }

        /// <summary>
        /// Преобразует объект класса <see cref="GostKeyTransport"/> 
        /// в байтовый массив.
        /// </summary>
        /// 
        /// <returns>Данные обмена ключами в виде байтового массива.</returns>
        public virtual byte[] Encode()
        {
            return this.Encode();
        }

        /// <summary>
        /// Восстанавливает объект класса <see cref="GostKeyTransport"/> 
        /// из байтового массива.
        /// </summary>
        /// 
        /// <param name="data">Данные для обмена в виде байтового 
        /// массива.</param>
        /// 
        /// <returns>Данные для обмена в объекта класса 
        /// <see cref="GostKeyTransport"/>.</returns>
        public void Decode(byte[] data)
        {
            this.Decode(data);
        }
    }

    /// <summary>
    /// Зашифрованная для передачи ключевая информация.
    /// </summary>
    /// 
    /// <remarks>
    /// Синхропосылка не входит в класс <c>GostKeyTransport</c> и должна 
    /// передаваться отдельно.
    /// </remarks>
    /// 
    /// <doc-sample path="Simple\Encrypt" name="KeyExchange">Пример использования 
    /// класса GostKeyTransport для передачи ключевой информации.</doc-sample>
    [Serializable, StructLayout(LayoutKind.Sequential)]
    public struct GostKeyTransport
    {
        /// <summary>
        /// Зашифрованный сессионный ключ.
        /// </summary>
        public GostWrappedKey SessionEncryptedKey;

        /// <summary>
        /// Параметры алгоритма ГОСТ Р 34.10.
        /// </summary>
        public Gost3410Parameters TransportParameters;

        /// <summary>
        /// Преобразует объект класса <see cref="GostKeyTransport"/> 
        /// в байтовый массив.
        /// </summary>
        /// 
        /// <returns>Данные обмена ключами в виде байтового массива.</returns>
        public byte[] Encode()
        {
            GostKeyTransportObject obj = new GostKeyTransportObject();
            obj.Transport = this;
            return obj.Encode();
        }

        /// <summary>
        /// Восстанавливает объект класса <see cref="GostKeyTransport"/> 
        /// из байтового массива.
        /// </summary>
        /// 
        /// <param name="data">Данные для обмена в виде байтового 
        /// массива.</param>
        /// 
        /// <returns>Данные для обмена в объекта класса 
        /// <see cref="GostKeyTransport"/>.</returns>
        public void Decode(byte[] data)
        {
            GostKeyTransportObject obj = new GostKeyTransportObject();
            obj.Decode(data);
            this = obj.Transport;
        }
    }
}
