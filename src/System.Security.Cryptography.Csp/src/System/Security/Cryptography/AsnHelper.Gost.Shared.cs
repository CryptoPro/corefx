using System;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Internal.Cryptography;
using static Internal.NativeCrypto.CapiHelper;

namespace Internal.NativeCrypto
{
    internal static partial class AsnHelper
    {
        /// <summary>
        /// Кодирование Public ключа ГОСТ 34.10 в BLOB для импорта.
        /// </summary>
        /// 
        /// <param name="cspObject">Открытый ключ с параметрами.</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <returns>BLOB для импорта.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. У нас функция используется еще 
        /// и при разборе открытого клуча в обходе
        /// CryptoPro.Sharpei.NetDetours.CPPublicKey.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static byte[] EncodePublicBlob(Gost3410CspObject cspObject, CspAlgorithmType alg)
        {
            int keySize;
            int algId;

            switch (alg)
            {
                case CspAlgorithmType.Gost2001:
                    keySize = GostConstants.GOST_3410EL_SIZE;
                    algId = GostConstants.CALG_GR3410EL;
                    break;
                case CspAlgorithmType.Gost2012_256:
                    keySize = GostConstants.GOST3410_2012_256KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_256;
                    break;
                case CspAlgorithmType.Gost2012_512:
                    keySize = GostConstants.GOST3410_2012_512KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_512;
                    break;
                default:
                    throw new CryptographicException(SR.Cryptography_CSP_WrongKeySpec);
            }

            if (cspObject == null)
                throw new ArgumentNullException("cspObject");

            byte[] encodedParameters = cspObject.EncodeParameters();

            byte[] data = new byte[16 + encodedParameters.Length
                + cspObject._publicKey.Length];
            data[0] = GostConstants.PUBLICKEYBLOB;
            data[1] = GostConstants.CSP_CUR_BLOB_VERSION;

            byte[] algid = BitConverter.GetBytes(algId);
            Array.Copy(algid, 0, data, 4, 4);

            byte[] magic = BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC);
            Array.Copy(magic, 0, data, 8, 4);

            byte[] bitlen = BitConverter.GetBytes(keySize);
            Array.Copy(bitlen, 0, data, 12, 4);

            Array.Copy(encodedParameters, 0, data, 16,
                encodedParameters.Length);
            Array.Copy(cspObject._publicKey, 0, data,
                16 + encodedParameters.Length,
                cspObject._publicKey.Length);
            return data;
        }

        /// <summary>
        /// Кодирование Public ключа ГОСТ 34.10 в BLOB для импорта.
        /// </summary>
        /// 
        /// <param name="keyBlob">Откытый ключ без параметров.</param>
        /// <param name="paramBlob">Параметры откытого ключа</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <returns>BLOB для импорта.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. У нас функция используется еще 
        /// и при разборе открытого клуча в обходе
        /// CryptoPro.Sharpei.NetDetours.CPPublicKey.</para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static byte[] EncodePublicBlob(byte[] keyBlob, byte[] paramBlob, CspAlgorithmType alg)
        {
            int keySize;
            int algId;

            switch (alg)
            {
                case CspAlgorithmType.Gost2001:
                    keySize = GostConstants.GOST_3410EL_SIZE;
                    algId = GostConstants.CALG_GR3410EL;
                    break;
                case CspAlgorithmType.Gost2012_256:
                    keySize = GostConstants.GOST3410_2012_256KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_256;
                    break;
                case CspAlgorithmType.Gost2012_512:
                    keySize = GostConstants.GOST3410_2012_512KEY_SIZE;
                    algId = GostConstants.CALG_GR3410_12_512;
                    break;
                default:
                    throw new CryptographicException(SR.Cryptography_CSP_WrongKeySpec);
            }

            byte[] data = new byte[16 + paramBlob.Length
                + keyBlob.Length];
            data[0] = GostConstants.PUBLICKEYBLOB;
            data[1] = GostConstants.CSP_CUR_BLOB_VERSION;

            byte[] algid = BitConverter.GetBytes(algId);
            Array.Copy(algid, 0, data, 4, 4);

            byte[] magic = BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC);
            Array.Copy(magic, 0, data, 8, 4);

            byte[] bitlen = BitConverter.GetBytes(keySize);
            Array.Copy(bitlen, 0, data, 12, 4);

            Array.Copy(paramBlob, 0, data, 16,
                paramBlob.Length);
            Array.Copy(keyBlob, 0, data,
                16 + paramBlob.Length,
                keyBlob.Length);
            return data;
        }

        /// <summary>
        /// Разбор BLOB открытого ключа ГОСТ 34.10.
        /// </summary>
        /// 
        /// <param name="obj">Gost3410CspObject</param>
        /// <param name="data">BLOB</param>
        /// <param name="alg">Тип алгоритма</param>
        /// 
        /// <argnull name="obj" />
        /// <exception cref="CryptographicException">Если 
        /// <paramref name="obj"/> не объект типа 
        /// <see cref="Gost3410CspObject"/></exception>
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. </para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void DecodePublicBlob(Object obj, byte[] data, CspAlgorithmType alg)
        {
            int keySize;

            switch (alg)
            {
                case CspAlgorithmType.Gost2001:
                    keySize = GostConstants.GOST_3410EL_SIZE;
                    break;
                case CspAlgorithmType.Gost2012_256:
                    keySize = GostConstants.GOST3410_2012_256KEY_SIZE;
                    break;
                case CspAlgorithmType.Gost2012_512:
                    keySize = GostConstants.GOST3410_2012_512KEY_SIZE;
                    break;
                default:
                    throw new CryptographicException(SR.Cryptography_CSP_WrongKeySpec);
            }

            if (obj == null)
                throw new ArgumentNullException("obj");
            Gost3410CspObject cspObject = obj as Gost3410CspObject;
            if (cspObject == null)
                throw new CryptographicException(GostConstants.NTE_BAD_ALGID);
            if (data.Length < 16 + keySize / 8)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);

            // CRYPT_PUBKEYPARAM -> 8 { Magic, BitLen )
            uint magic = BitConverter.ToUInt32(data, 8);
            uint bitlen = BitConverter.ToUInt32(data, 12);
            if (magic != GostConstants.GR3410_1_MAGIC)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            if (bitlen != keySize)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);

            byte[] tmp = new byte[data.Length - 16 - keySize / 8];
            Array.Copy(data, 16, tmp, 0, data.Length - 16 - keySize / 8);


            var publicKeyParameters = new GostKeyExchangeParameters();
            var encodeKeyParameters = new byte[(data.Length - 16) - keySize / 8];
            Array.Copy(data, 16, encodeKeyParameters, 0, (data.Length - 16) - keySize / 8);
            publicKeyParameters.DecodeParameters(encodeKeyParameters);

            var publicKey = new byte[keySize / 8];
            Array.Copy(data, data.Length - keySize / 8, publicKey, 0, keySize / 8);
            publicKeyParameters.PublicKey = publicKey;

            cspObject._publicKey = publicKeyParameters.PublicKey;
            cspObject._publicKeyParamSet = publicKeyParameters.PublicKeyParamSet;
            cspObject._digestParamSet = publicKeyParameters.DigestParamSet;
        }

        /// <summary>
        /// Кодирование сессионного ключа в SIMPLE BLOB.
        /// </summary>
        /// 
        /// <param name="cspObject">Зашифрованный сессионный ключ.</param>
        /// <param name="algid">Алгоритм зашифрованного ключа.</param>
        /// 
        /// <returns>BLOB</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        /// <argnull name="cspObject" />
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. </para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static byte[] EncodeSimpleBlob(GostWrappedKeyObject cspObject, int algid)
        {
            if (cspObject == null)
                throw new ArgumentNullException("cspObject");

            byte[] par = AsnHelper.EncodeGost28147_89_BlobParameters(
                cspObject._encryptionParamSet);

            byte[] ret = new byte[16
                + GostConstants.SEANCE_VECTOR_LEN
                + GostConstants.G28147_KEYLEN
                + GostConstants.EXPORT_IMIT_SIZE
                + par.Length];
            int pos = 0;

            // CRYPT_SIMPLEBLOB_->CRYPT_SIMPLEBLOB_HEADER
            ret[pos] = GostConstants.SIMPLEBLOB;
            pos++;
            ret[pos] = GostConstants.CSP_CUR_BLOB_VERSION;
            pos++;

            pos += 2; // Reserved

            byte[] balgid = BitConverter.GetBytes(algid);
            Array.Copy(balgid, 0, ret, pos, 4);
            pos += 4;

            byte[] magic = BitConverter.GetBytes(GostConstants.SIMPLEBLOB_MAGIC);
            Array.Copy(magic, 0, ret, pos, 4);
            pos += 4;

            byte[] ealgid = BitConverter.GetBytes(GostConstants.CALG_G28147);
            Array.Copy(ealgid, 0, ret, pos, 4);
            pos += 4;

            // CRYPT_SIMPLEBLOB_->bSV
            Array.Copy(cspObject._ukm, 0, ret, pos, GostConstants.SEANCE_VECTOR_LEN);
            pos += GostConstants.SEANCE_VECTOR_LEN;

            // CRYPT_SIMPLEBLOB_->bEncryptedKey
            Array.Copy(cspObject._encryptedKey, 0, ret, pos, GostConstants.G28147_KEYLEN);
            pos += GostConstants.G28147_KEYLEN;

            // CRYPT_SIMPLEBLOB_->bMacKey
            Array.Copy(cspObject._mac, 0, ret, pos, GostConstants.EXPORT_IMIT_SIZE);
            pos += GostConstants.EXPORT_IMIT_SIZE;

            // CRYPT_SIMPLEBLOB_->bEncryptionParamSet
            Array.Copy(par, 0, ret, pos, par.Length);
            return ret;
        }

        /// <summary>
        /// Декодирование зашифрованного сессионного ключа из BLOB
        /// в структуру.
        /// </summary>
        /// 
        /// <param name="cspObject"><see cref="GostWrappedKeyObject"/></param>
        /// <param name="data">BLOB</param>
        /// 
        /// <argnull name="data" />
        /// <argnull name="cspObject" />
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования структуры.</exception>
        /// 
        /// <intdoc><para>Аналог в MS отсутствует, часть реализации
        /// присутствует в ImportKey. </para></intdoc>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal static void DecodeSimpleBlob(GostWrappedKeyObject cspObject, byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (cspObject == null)
                throw new ArgumentNullException("cspObject");
            if (data.Length < 16 + 0)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            // CRYPT_SIMPLEBLOB_HEADER_->BLOB_HEADER.aiKeyAlg ->4
            uint aiKeyAlg = BitConverter.ToUInt32(data, 4);
            if (aiKeyAlg != GostConstants.CALG_G28147)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            // CRYPT_SIMPLEBLOB_HEADER_-> 8 (Magic, EncryptKeyAlgId)
            uint magic = BitConverter.ToUInt32(data, 8);
            if (magic != GostConstants.SIMPLEBLOB_MAGIC)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            uint EncryptKeyAlgId = BitConverter.ToUInt32(data, 12);
            if (EncryptKeyAlgId != GostConstants.CALG_G28147)
                throw new CryptographicException(GostConstants.NTE_BAD_DATA);
            // CRYPT_SIMPLEBLOB_->bSV
            int pos = 16;
            cspObject._ukm = new byte[GostConstants.SEANCE_VECTOR_LEN];
            Array.Copy(data, pos, cspObject._ukm, 0, GostConstants.SEANCE_VECTOR_LEN);
            pos += GostConstants.SEANCE_VECTOR_LEN;
            // CRYPT_SIMPLEBLOB_->bEncryptedKey
            cspObject._encryptedKey = new byte[GostConstants.G28147_KEYLEN];
            Array.Copy(data, pos, cspObject._encryptedKey, 0, GostConstants.G28147_KEYLEN);
            pos += GostConstants.G28147_KEYLEN;
            // CRYPT_SIMPLEBLOB_->bMacKey
            cspObject._mac = new byte[GostConstants.EXPORT_IMIT_SIZE];
            Array.Copy(data, pos, cspObject._mac, 0, GostConstants.EXPORT_IMIT_SIZE);
            pos += GostConstants.EXPORT_IMIT_SIZE;
            // CRYPT_SIMPLEBLOB_->bEncryptionParamSet
            byte[] tmp = new byte[data.Length - pos];
            Array.Copy(data, pos, tmp, 0, data.Length - pos);
            cspObject._encryptionParamSet = AsnHelper.DecodeGost28147_89_BlobParameters(tmp);
        }

        /// <summary>
        /// ASN1c структура параметров шифрования.
        /// </summary>
        /// 
        /// <param name="val">Строковое представление OID парамтеров 
        /// шифрования.</param>
        /// 
        /// <returns>ASN1c структура параметров шифрования или 
        /// <see langword="null"/> при <see langword="null"/> входной 
        /// строке.</returns>
        private static Gost28147_89_ParamSet CreateGost28147_89_ParamSet(
            string val)
        {
            if (val == null)
                return null;
            return new Gost28147_89_ParamSet(FromString(val).Value);
        }

        /// <summary>
        /// Декодирование Asn1c OID.
        /// </summary>
        /// 
        /// <param name="id">OID в виде ASN1c.</param>
        /// 
        /// <returns>Строковое представление oid или <see langword="null"/>,
        /// если входная строка <see langword="null"/>.</returns>
        private static string ToString(Asn1ObjectIdentifier id)
        {
            if (id == null)
                return null;
            StringBuilder b = new StringBuilder(id.Value.Length * 10);
            foreach (int i in id.Value)
                b.Append("." + i);
            return b.ToString().Substring(1);
        }

        /// <summary>
        /// ASN1c кодирование OID из строкового представления.
        /// </summary>
        /// 
        /// <param name="oid">строковое представление OID.</param>
        /// 
        /// <returns>OID в представлении asn1c или <see langword="null"/>, 
        /// если входная строка <see langword="null"/>.</returns>
        /// 
        /// <exception cref="CryptographicException">при неправильном
        /// представлении OID.</exception>
        private static Asn1ObjectIdentifier FromString(string oid)
        {
            if (oid == null)
                return null;
            int i = 1;
            foreach (char c in oid)
                if (c == '.')
                    i++;
            int[] ar = new int[i];
            int p = 0;
            i = 0;
            while (p < oid.Length)
            {
                char c = oid[p];
                if (!Char.IsDigit(c))
                    throw new CryptographicException(
                        "Asn1ObjectIdentifier");
                int k = 0;
                while (p < oid.Length)
                {
                    c = oid[p++];
                    if (c == '.')
                        break;
                    if (!Char.IsDigit(c))
                        throw new CryptographicException(
                            "Asn1ObjectIdentifier");
                    k = k * 10 + (int)c - '0';
                }
                ar[i++] = k;
            }
            return new Asn1ObjectIdentifier(ar);
        }

        /// <summary>
        /// Кодирование ASN.1 структуры зашифрованного ключа.
        /// </summary>
        /// 
        /// <param name="wk">Зашифрованный ключ.</param>
        /// 
        /// <returns>Закодированная структура.</returns>
        /// 
        /// <argnull name="wk" />
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования исходной структуры.</exception>
        public static byte[] EncodeXmlGostR3410WrappedKey(GostWrappedKeyObject wk)
        {
            GostR3410_KeyWrap wrapped = new GostR3410_KeyWrap();
            Asn1BerEncodeBuffer buffer = new Asn1BerEncodeBuffer();
            wrapped.encryptedKey = new Gost28147_89_EncryptedKey();
            wrapped.encryptedKey.macKey = new Gost28147_89_MAC(wk._mac);
            wrapped.encryptedKey.encryptedKey = new Gost28147_89_Key(wk._encryptedKey);
            wrapped.encryptedParameters = new Gost28147_89_KeyWrapParameters();
            wrapped.encryptedParameters.ukm = new Asn1OctetString(wk._ukm);
            wrapped.encryptedParameters.encryptionParamSet =
                CreateGost28147_89_ParamSet(wk._encryptionParamSet);
            wrapped.Encode(buffer);
            return buffer.MsgCopy;
        }

        /// <summary>
        /// Декодирование ASN.1 структуры зашифрованного общего секрета.
        /// </summary>
        /// 
        /// <param name="data">ASN.1 закодированная структура.</param>
        /// <param name="wk">Зашифрованный ГОСТ Р 34.10 ключ.</param>
        /// 
        /// <argnull name="data" />
        /// <argnull name="wk" />
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования исходной структуры.</exception>
        public static void DecodeXmlGostR3410WrappedKey(byte[] data,
            GostWrappedKeyObject wk)
        {
            Asn1BerDecodeBuffer buffer = new Asn1BerDecodeBuffer(data);
            GostR3410_KeyWrap wrapped = new GostR3410_KeyWrap();
            wrapped.Decode(buffer);
            wk._encryptedKey = wrapped.encryptedKey.encryptedKey.Value;
            wk._mac = wrapped.encryptedKey.macKey.Value;
            wk._ukm = wrapped.encryptedParameters.ukm.Value;
            wk._encryptionParamSet = ToString(
                wrapped.encryptedParameters.encryptionParamSet);
        }

        /// <summary>
        /// Декодирование ASN.1 структуры параметров шифрования.
        /// </summary>
        /// 
        /// <param name="data">ASN.1 закодированные параметры
        /// шифровыания.</param>
        /// 
        /// <returns>Строковое представление OID шифрования.</returns>
        /// 
        /// <argnull name="data" />
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования исходной структуры.</exception>
        public static string DecodeGost28147_89_BlobParameters(
            byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");
                Asn1BerDecodeBuffer buffer =
                    new Asn1BerDecodeBuffer(data);
                Gost28147_89_BlobParameters asnParams =
                    new Gost28147_89_BlobParameters();
                asnParams.Decode(buffer);
                return ToString(asnParams.encryptionParamSet);
        }

        /// <summary>
        /// ASN.1 кодирование структуры параметров шифрования.
        /// </summary>
        /// 
        /// <param name="parameters">OID параметров шифрования.</param>
        /// 
        /// <returns>Закодированная ASN.1 структура.</returns>
        /// 
        /// <argnull name="parameters" />
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования структуры.</exception>
        public static byte[] EncodeGost28147_89_BlobParameters(
            string parameters)
        {
            if (parameters == null)
                throw new ArgumentNullException("parameters");
            Asn1BerEncodeBuffer buffer = new Asn1BerEncodeBuffer();
            Gost28147_89_BlobParameters asnParams =
                new Gost28147_89_BlobParameters();
                asnParams.encryptionParamSet =
                    CreateGost28147_89_ParamSet(parameters);
                asnParams.Encode(buffer);
                return buffer.MsgCopy;
        }

        /// <summary>
        /// Декодирование ASN.1 структуры транспорта. 
        /// </summary>
        /// 
        /// <param name="data">ASN.1 закодированная структура.</param>
        /// <param name="transport">ГОСТ Р 34.10 транспорт.</param>
        /// 
        /// <argnull name="data" />
        /// <exception cref="CryptographicException">При ошибках
        /// декодирования исходной структуры.</exception>
        public static void DecodeGostKeyTransport(byte[] data,
            GostKeyTransportObject transport)
        {
            if (data == null)
                throw new ArgumentNullException("data");
            if (transport == null)
                throw new ArgumentNullException("transport");
            try
            {
                Asn1BerDecodeBuffer buffer = new Asn1BerDecodeBuffer(data);
                GostR3410_KeyTransport asnTransport =
                    new GostR3410_KeyTransport();
                asnTransport.Decode(buffer);
                transport.sessionEncryptedKey_ = new GostWrappedKeyObject();
                transport.sessionEncryptedKey_._encryptedKey =
                    asnTransport.sessionEncryptedKey.encryptedKey.Value;
                transport.sessionEncryptedKey_._mac =
                    asnTransport.sessionEncryptedKey.macKey.Value;
                transport.sessionEncryptedKey_._ukm =
                    asnTransport.transportParameters.ukm.Value;
                transport.sessionEncryptedKey_._encryptionParamSet =
                    toString(asnTransport.transportParameters.encryptionParamSet);
                // Для корректной ошибки, а не ArgumentException
                string algoid = toString(
                    asnTransport.transportParameters.ephemeralPublicKey.
                    algorithm.algorithm);

                if (algoid.Equals(GostConstants.OID_CP_GOST_R3410EL))
                {
                    transport.transportParameters_ = UnpackPublicKeyInfo2001(
                        asnTransport.transportParameters.ephemeralPublicKey);
                }
                else if (algoid.Equals(GostConstants.OID_CP_GOST_R3410_12_256) ||
                    (algoid.Equals(GostConstants.OID_CP_GOST_R3410_12_512)))
                {
                    transport.transportParameters_ = UnpackPublicKeyInfo2012(
                        asnTransport.transportParameters.ephemeralPublicKey);
                }
                else
                {
                    throw new CryptographicException(
                        "Resources.Cryptography_ASN1_Decode_Alg " + algoid);
                }

            }
            catch (Exception e)
            {
                throw new CryptographicException(
                    "Resources.Cryptography_ASN1_DecodeWithException " +
                    "GostR3410_KeyTransport", e);
            }
        }

        /// <summary>
        /// ASN.1 кодирование структуры транспорта. 
        /// </summary>
        /// 
        /// <param name="transport">ASN.1 транспорт.</param>
        /// 
        /// <returns>Закодированная структура.</returns>
        /// 
        /// <argnull name="transport" />
        /// <exception cref="CryptographicException">При ошибках
        /// кодирования исходной структуры.</exception>
        public static byte[] EncodeGostKeyTransport(
            GostKeyTransportObject transport)
        {
            if (transport == null)
                throw new ArgumentNullException("transport");

            GostR3410_KeyTransport asnTransport =
                new GostR3410_KeyTransport();
            Asn1BerEncodeBuffer buffer = new Asn1BerEncodeBuffer();
            try
            {
                asnTransport.sessionEncryptedKey =
                    new Gost28147_89_EncryptedKey();
                asnTransport.sessionEncryptedKey.encryptedKey =
                    new Gost28147_89_Key(
                        transport.sessionEncryptedKey_._encryptedKey);
                asnTransport.sessionEncryptedKey.macKey =
                    new Gost28147_89_MAC(transport.sessionEncryptedKey_._mac);
                asnTransport.transportParameters =
                    new GostR3410_TransportParameters();
                asnTransport.transportParameters.ukm =
                    new Asn1OctetString(transport.sessionEncryptedKey_._ukm);
                asnTransport.transportParameters.encryptionParamSet =
                    CreateGost28147_89_ParamSet(
                        transport.sessionEncryptedKey_._encryptionParamSet);

                if (transport.Transport.TransportParameters.DigestParamSet == "1.2.643.2.2.30.1")
                {
                    asnTransport.transportParameters.ephemeralPublicKey =
                        PackPublicKeyInfo2001(transport.transportParameters_);
                }
                else if (transport.Transport.TransportParameters.DigestParamSet == "1.2.643.7.1.1.2.2")
                {
                    asnTransport.transportParameters.ephemeralPublicKey =
                      PackPublicKeyInfo2012_256(transport.transportParameters_);
                }
                else if (transport.Transport.TransportParameters.DigestParamSet == "1.2.643.7.1.1.2.3")
                {
                    asnTransport.transportParameters.ephemeralPublicKey =
                      PackPublicKeyInfo2012_512(transport.transportParameters_);
                }
                asnTransport.Encode(buffer);
            }
            catch (Exception e)
            {
                throw new CryptographicException(
                    "Resources.Cryptography_ASN1_EncodeWithException " +
                    "GostR3410_KeyTransport", e);
            }
            return buffer.MsgCopy;
        }

        /// <summary>
        /// Упаковка открытого ключа ГОСТ 34.10 и его параметров в Asn1c структуру.
        /// </summary>
        /// 
        /// <param name="pub">Открытый ключ.</param>
        /// <param name="alg"></param>
        /// 
        /// <returns>Asn1c структура <c>SubjectPublicKeyInfo</c> открытого
        /// ключа.</returns>
        /// 
        private static SubjectPublicKeyInfo PackPublicKeyInfo(
            Gost3410CspObject pub, CspAlgorithmType alg)
        {
            switch (alg)
            {
                case CspAlgorithmType.Gost2001:
                    return PackPublicKeyInfo2001(pub);
                case CspAlgorithmType.Gost2012_256:
                    return PackPublicKeyInfo2012_256(pub);
                case CspAlgorithmType.Gost2012_512:
                    return PackPublicKeyInfo2012_512(pub);
                default:
                    throw new CryptographicException(
                        "Cryptography_CSP_WrongKeySpec");
            }
        }

        /// <summary>
        /// Упаковка открытого ключа ГОСТ 34.10-2001 и его параметров в Asn1c структуру.
        /// </summary>
        /// 
        /// <param name="pub">Открытый ключ.</param>
        /// 
        /// <returns>Asn1c структура <c>SubjectPublicKeyInfo</c> открытого
        /// ключа.</returns>
        /// 
        private static SubjectPublicKeyInfo PackPublicKeyInfo2001(
            Gost3410CspObject pub)
        {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
            Asn1BerEncodeBuffer buffer = new Asn1BerEncodeBuffer();
            Asn1OctetString publicKey = new Asn1OctetString(pub._publicKey);
            publicKey.Encode(buffer);
            byte[] octetString = buffer.MsgCopy;
            spki.subjectPublicKey = new Asn1BitString(
                octetString.Length * 8, octetString);
            GostR3410_2001_PublicKeyParameters par =
                new GostR3410_2001_PublicKeyParameters();
            par.PublicKeyParamSet = fromString(pub._publicKeyParamSet);
            par.DigestParamSet = fromString(pub._digestParamSet);
            par.EncryptionParamSet = CreateGost28147_89_ParamSet(
                pub._encryptionParamSet);
            buffer.Reset();
            par.Encode(buffer);
            spki.algorithm = new AlgorithmIdentifier(
                fromString(GostConstants.OID_CP_GOST_R3410EL),
                new Asn1OpenType(buffer.MsgCopy));
            return spki;
        }

        /// <summary>
        /// Упаковка открытого ключа ГОСТ 34.10-2012 256 и его параметров в Asn1c структуру.
        /// </summary>
        /// 
        /// <param name="pub">Открытый ключ.</param>
        /// 
        /// <returns>Asn1c структура <c>SubjectPublicKeyInfo</c> открытого
        /// ключа.</returns>
        private static SubjectPublicKeyInfo PackPublicKeyInfo2012_256(
            Gost3410CspObject pub)
        {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
            Asn1BerEncodeBuffer buffer = new Asn1BerEncodeBuffer();
            Asn1OctetString publicKey = new Asn1OctetString(pub._publicKey);
            publicKey.Encode(buffer);
            byte[] octetString = buffer.MsgCopy;
            spki.subjectPublicKey = new Asn1BitString(
                octetString.Length * 8, octetString);
            GostR3410_2012_PublicKeyParameters par =
                new GostR3410_2012_PublicKeyParameters();
            par.publicKeyParamSet = fromString(pub._publicKeyParamSet);
            par.digestParamSet = fromString(pub._digestParamSet);
            par.encryptionParamSet = CreateGost28147_89_ParamSet(
                pub._encryptionParamSet);
            buffer.Reset();
            par.Encode(buffer);
            spki.algorithm = new AlgorithmIdentifier(
                fromString(GostConstants.OID_CP_GOST_R3410_12_256),
                new Asn1OpenType(buffer.MsgCopy));
            return spki;
        }

        /// <summary>
        /// Упаковка открытого ключа ГОСТ 34.10-2012 512 и его параметров в Asn1c структуру.
        /// </summary>
        /// 
        /// <param name="pub">Открытый ключ.</param>
        /// 
        /// <returns>Asn1c структура <c>SubjectPublicKeyInfo</c> открытого
        /// ключа.</returns>
        private static SubjectPublicKeyInfo PackPublicKeyInfo2012_512(
            Gost3410CspObject pub)
        {
            SubjectPublicKeyInfo spki = new SubjectPublicKeyInfo();
            Asn1BerEncodeBuffer buffer = new Asn1BerEncodeBuffer();
            Asn1OctetString publicKey = new Asn1OctetString(pub._publicKey);
            publicKey.Encode(buffer);
            byte[] octetString = buffer.MsgCopy;
            spki.subjectPublicKey = new Asn1BitString(
                octetString.Length * 8, octetString);
            GostR3410_2012_PublicKeyParameters par =
                new GostR3410_2012_PublicKeyParameters();
            par.publicKeyParamSet = fromString(pub._publicKeyParamSet);
            par.digestParamSet = fromString(pub._digestParamSet);
            par.encryptionParamSet = CreateGost28147_89_ParamSet(
                pub._encryptionParamSet);
            buffer.Reset();
            par.Encode(buffer);
            spki.algorithm = new AlgorithmIdentifier(
                fromString(GostConstants.OID_CP_GOST_R3410_12_512),
                new Asn1OpenType(buffer.MsgCopy));
            return spki;
        }


        /// <summary>
        /// Разбор декодированной ASN1c структуры ГОСТ 34.10 <c>SubjectPublicKeyInfo</c>.
        /// </summary>
        /// 
        /// <param name="spki">ASN1c структура <c>SubjectPublicKeyInfo</c>.
        /// </param>
        /// <param name="alg"></param>
        /// 
        /// <returns>Параметры открытого ключа.</returns>
        /// <argnull name="spki" />
        /// <exception cref="ArgumentException">Если вложенная структура 
        /// не приводится к <c>GostR3410_2001_PublicKeyParameters</c>
        /// </exception>
        private static Gost3410CspObject UnpackPublicKeyInfo(
            SubjectPublicKeyInfo spki, CspAlgorithmType alg)
        {
            switch (alg)
            {
                case CspAlgorithmType.Gost2001:
                    return UnpackPublicKeyInfo2001(spki);
                case CspAlgorithmType.Gost2012_256:
                case CspAlgorithmType.Gost2012_512:
                    return UnpackPublicKeyInfo2012(spki);
                default:
                    throw new CryptographicException(
                        "Cryptography_CSP_WrongKeySpec");
            }
        }

        /// <summary>
        /// Разбор декодированной ASN1c структуры ГОСТ 34.10-2001 <c>SubjectPublicKeyInfo</c>.
        /// </summary>
        /// 
        /// <param name="spki">ASN1c структура <c>SubjectPublicKeyInfo</c>.
        /// </param>
        /// 
        /// <returns>Параметры открытого ключа.</returns>
        /// <argnull name="spki" />
        /// <exception cref="ArgumentException">Если вложенная структура 
        /// не приводится к <c>GostR3410_2001_PublicKeyParameters</c>
        /// </exception>
        private static Gost3410CspObject UnpackPublicKeyInfo2001(
            SubjectPublicKeyInfo spki)
        {
            if (spki == null)
                throw new ArgumentNullException("spki");
            Asn1Choice choice = spki.algorithm.parameters as Asn1Choice;
            if (choice == null)
                throw new ArgumentException(
                    "spki.algorithm.parameters");
            GostR3410_2001_PublicKeyParameters publicKeyParameters =
                choice.GetElement() as GostR3410_2001_PublicKeyParameters;
            if (publicKeyParameters == null)
                throw new ArgumentException(
                    "spki.algorithm.parameters.element");
            byte[] bitString = spki.subjectPublicKey.Value;
            Asn1BerDecodeBuffer buffer = new Asn1BerDecodeBuffer(bitString);
            Asn1OctetString publicKey = new Asn1OctetString();
            publicKey.Decode(buffer);
            Gost3410CspObject ret = new Gost3410CspObject();
            ret._publicKeyParamSet = toString(
                publicKeyParameters.PublicKeyParamSet);
            ret._digestParamSet = toString(
                publicKeyParameters.DigestParamSet);
            ret._encryptionParamSet = toString(
                publicKeyParameters.EncryptionParamSet);
            ret._publicKey = publicKey.Value;
            ret._privateKey = null;
            return ret;
        }

        /// <summary>
        /// Разбор декодированной ASN1c структуры ГОСТ 34.10-2012 <c>SubjectPublicKeyInfo</c>.
        /// </summary>
        /// 
        /// <param name="spki">ASN1c структура <c>SubjectPublicKeyInfo</c>.
        /// </param>
        /// 
        /// <returns>Параметры открытого ключа.</returns>
        /// <argnull name="spki" />
        /// <exception cref="ArgumentException">Если вложенная структура 
        /// не приводится к <c>GostR3410_2001_PublicKeyParameters</c>
        /// </exception>
        private static Gost3410CspObject UnpackPublicKeyInfo2012(
            SubjectPublicKeyInfo spki)
        {
            if (spki == null)
                throw new ArgumentNullException("spki");
            Asn1Choice choice = spki.algorithm.parameters as Asn1Choice;
            if (choice == null)
                throw new ArgumentException(
                    "spki.algorithm.parameters");
            GostR3410_2012_PublicKeyParameters publicKeyParameters =
                choice.GetElement() as GostR3410_2012_PublicKeyParameters;
            if (publicKeyParameters == null)
                throw new ArgumentException(
                    "spki.algorithm.parameters.element");
            byte[] bitString = spki.subjectPublicKey.Value;
            Asn1BerDecodeBuffer buffer = new Asn1BerDecodeBuffer(bitString);
            Asn1OctetString publicKey = new Asn1OctetString();
            publicKey.Decode(buffer);
            Gost3410CspObject ret = new Gost3410CspObject();
            ret._publicKeyParamSet = toString(
                publicKeyParameters.publicKeyParamSet);
            ret._digestParamSet = toString(
                publicKeyParameters.digestParamSet);
            ret._encryptionParamSet = toString(
                publicKeyParameters.encryptionParamSet);
            ret._publicKey = publicKey.Value;
            ret._privateKey = null;
            return ret;
        }

        /// <summary>
        /// Декодирование Asn1c OID.
        /// </summary>
        /// 
        /// <param name="id">OID в виде ASN1c.</param>
        /// 
        /// <returns>Строковое представление oid или <see langword="null"/>,
        /// если входная строка <see langword="null"/>.</returns>
        private static string toString(Asn1ObjectIdentifier id)
        {
            if (id == null)
                return null;
            StringBuilder b = new StringBuilder(id.Value.Length * 10);
            foreach (int i in id.Value)
                b.Append("." + i);
            return b.ToString().Substring(1);
        }

        /// <summary>
        /// ASN1c кодирование OID из строкового представления.
        /// </summary>
        /// 
        /// <param name="oid">строковое представление OID.</param>
        /// 
        /// <returns>OID в представлении asn1c или <see langword="null"/>, 
        /// если входная строка <see langword="null"/>.</returns>
        /// 
        /// <exception cref="CryptographicException">при неправильном
        /// представлении OID.</exception>
        private static Asn1ObjectIdentifier fromString(string oid)
        {
            if (oid == null)
                return null;
            int i = 1;
            foreach (char c in oid)
                if (c == '.')
                    i++;
            int[] ar = new int[i];
            int p = 0;
            i = 0;
            while (p < oid.Length)
            {
                char c = oid[p];
                if (!Char.IsDigit(c))
                    throw new CryptographicException(
                        "Resources.Cryptography_ASN1_EncodeWithValue " +
                        "Asn1ObjectIdentifier " + oid);
                int k = 0;
                while (p < oid.Length)
                {
                    c = oid[p++];
                    if (c == '.')
                        break;
                    if (!Char.IsDigit(c))
                        throw new CryptographicException(
                        "Resources.Cryptography_ASN1_EncodeWithValue " +
                        "Asn1ObjectIdentifier " + oid);
                    k = k * 10 + (int)c - '0';
                }
                ar[i++] = k;
            }
            try
            {
                return new Asn1ObjectIdentifier(ar);
            }
            catch (Exception e)
            {
                throw new CryptographicException(
                    "Resources.Cryptography_ASN1_EncodeWithException " +
                    "Asn1ObjectIdentifier", e);
            }
        }
    }
}
