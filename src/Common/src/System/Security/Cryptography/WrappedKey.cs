using System.Runtime.InteropServices;
using System.Text;
using Internal.NativeCrypto;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Структура зашифрованного на алгоритме ГОСТ 28147 ключа.
    /// </summary>
    /// 
    /// <remarks>
    /// Данный класс служит для передачи ключевой информации, например, 
    /// сессионных ключей.
    /// </remarks>
    internal class GostWrappedKeyObject
    {
        /// <summary>
        /// OID параметров шифрования.
        /// </summary>
        internal string _encryptionParamSet;
        /// <summary>
        /// UKM.
        /// </summary>
        internal byte[] _ukm;
        /// <summary>
        /// Зашифрованный ключ.
        /// </summary>
        internal byte[] _encryptedKey;
        /// <summary>
        /// Message Authentication Code.
        /// </summary>
        internal byte[] _mac;

        /// <summary>
        /// Упаковка в ASN.1 структуру Gost3410-KeyWrap.
        /// </summary>
        /// <returns>Байтовый массив ASN.1 структуры Gost3410-KeyWrap.</returns>
        public byte[] GetXmlWrappedKey()
        {
            return AsnHelper.EncodeXmlGostR3410WrappedKey(this);
        }

        /// <summary>
        /// Получение структуры зашифрованного ключа на основе 
        /// ASN.1 структуру Gost3410-KeyWrap.
        /// </summary>
        /// <param name="data">ASN.1 структура Gost3410-KeyWrap</param>
        public void SetByXmlWrappedKey(byte[] data)
        {
            AsnHelper.DecodeXmlGostR3410WrappedKey(data, this);
        }

        public GostWrappedKey WrappedKey
        {
            get
            {
                GostWrappedKey ret;
                ret.EncryptionParamSet = _encryptionParamSet;
                ret.Ukm = _ukm;
                ret.EncryptedKey = _encryptedKey;
                ret.Mac = _mac;
                return ret;
            }
            set
            {
                this._encryptionParamSet = value.EncryptionParamSet;
                this._ukm = value.Ukm;
                this._encryptedKey = value.EncryptedKey;
                this._mac = value.Mac;
            }
        }        
    }

    /// <summary>
    /// Структура зашифрованного на алгоритме ГОСТ 28147 ключа.
    /// </summary>
    /// 
    /// <remarks>
    /// Данный класс служит для передачи ключевой информации, например, 
    /// сессионных ключей.
    /// </remarks>
    /// 
    [Serializable, StructLayout(LayoutKind.Sequential)]
    public struct GostWrappedKey
    {
        /// <summary>
        /// Контрольная сумма (Message Authentication Code) зашифрованного 
        /// ключа.
        /// </summary>
        public byte[] Mac;

        /// <summary>
        /// UserKeyingMaterial
        /// </summary>
        public byte[] Ukm;

        /// <summary>
        /// OID параметров шифрования.
        /// </summary>
        public string EncryptionParamSet;

        /// <summary>
        /// Зашифрованный ключ.
        /// </summary>
        public byte[] EncryptedKey;

        /// <summary>
        /// Упаковка в ASN.1 структуру Gost3410-KeyWrap.
        /// </summary>
        /// <returns>Байтовый массив ASN.1 структуры Gost3410-KeyWrap.</returns>
        public byte[] GetXmlWrappedKey()
        {
            GostWrappedKeyObject obj = new GostWrappedKeyObject();
            obj.WrappedKey = this;
            return obj.GetXmlWrappedKey();
        }

        /// <summary>
        /// Упаковка в SIMPLE_BLOB.
        /// </summary>
        /// <returns>Байтовый массив SIMPLE_BLOB.</returns>
        /// <exception cref="System.Security.Cryptography.CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        /// 
        /// <cspversions />
        public byte[] GetCryptoServiceProviderBlob()
        {
            GostWrappedKeyObject obj = new GostWrappedKeyObject();
            obj.WrappedKey = this;
            return AsnHelper.EncodeSimpleBlob(obj,
                GostConstants.CALG_G28147);
        }

        /// <summary>
        /// Получение структуры зашифрованного ключа на основе 
        /// ASN.1 структуру Gost3410-KeyWrap.
        /// </summary>
        /// <param name="data">ASN.1 структура Gost3410-KeyWrap</param>
        public void SetByXmlWrappedKey(byte[] data)
        {
            GostWrappedKeyObject obj = new GostWrappedKeyObject();
            obj.SetByXmlWrappedKey(data);
            this = obj.WrappedKey;
        }

        /// <summary>
        /// Распаковка объекта из SIMPLE_BLOB.
        /// </summary>
        /// <param name="data">Данные, закодированный SIMPLE_BLOB.</param>
        /// <exception cref="System.Security.Cryptography.CryptographicException">При ошибках
        /// декодирования структуры.</exception>
        /// <argnull name="data" />
        /// 
        /// <cspversions />
        public void SetByCryptoServiceProviderBlob(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            GostWrappedKeyObject obj = new GostWrappedKeyObject();
            AsnHelper.DecodeSimpleBlob(obj, data);
            this = obj.WrappedKey;
        }
    }
}
