// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    /// <summary>
    /// Переходник от структуры <see cref="Gost3410Parameters"/> к объекту.
    /// </summary>
    /// 
    internal class Gost3410CspObject
    {
        /// <summary>
        /// Конструктор объекта класса <see cref="Gost3410CspObject"/>
        /// </summary>
        public Gost3410CspObject()
        {
        }

        /// <summary>
        /// Конструктор объекта класса по параметрам ключа.
        /// </summary>
        public Gost3410CspObject(Gost3410Parameters parameters)
        {
            _publicKeyParamSet = parameters.PublicKeyParamSet;
            _digestParamSet = parameters.DigestParamSet;
            _encryptionParamSet = parameters.EncryptionParamSet;
            _publicKey = parameters.PublicKey;
            _privateKey = parameters.PrivateKey;
        }

        /// <summary>
        /// Получение/установка параметров ключа.
        /// </summary>
        public Gost3410Parameters Parameters
        {
            get
            {
                Gost3410Parameters ret;
                ret.PublicKeyParamSet = _publicKeyParamSet;
                ret.DigestParamSet = _digestParamSet;
                ret.EncryptionParamSet = _encryptionParamSet;
                ret.PublicKey = _publicKey;
                ret.PrivateKey = _privateKey;
                return ret;
            }
            set
            {
                _publicKeyParamSet = value.PublicKeyParamSet;
                _digestParamSet = value.DigestParamSet;
                _encryptionParamSet = value.EncryptionParamSet;
                _publicKey = value.PublicKey;
                _privateKey = value.PrivateKey;
            }
        }

        public void DecodeParameters(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }


            var asnDecoder = new Asn1BerDecodeBuffer(data);
            var publicKeyParameters = new Gost3410PublicKeyParameters();
            publicKeyParameters.Decode(asnDecoder);

            _digestParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.DigestParamSet);
            _publicKeyParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.PublicKeyParamSet);
            _encryptionParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.EncryptionParamSet);
        }


        public byte[] EncodeParameters()
        {
            byte[] data;

            var publicKeyParameters = new Gost3410PublicKeyParameters();

            publicKeyParameters.DigestParamSet = Asn1ObjectIdentifier.FromOidString(_digestParamSet);
            publicKeyParameters.PublicKeyParamSet = Asn1ObjectIdentifier.FromOidString(_publicKeyParamSet);
            publicKeyParameters.EncryptionParamSet = GostKeyExchangeParameters.CreateEncryptionParamSet(_encryptionParamSet);

            var asnEncoder = new Asn1BerEncodeBuffer();
            publicKeyParameters.Encode(asnEncoder);
            data = asnEncoder.MsgCopy;

            return data;
        }


        public void DecodePublicKey(byte[] data, int algId)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            Asn1OctetString publicKey;
            var asnDecoder = new Asn1BerDecodeBuffer(data);
            if (algId == GostConstants.CALG_GR3410EL)
            {
                publicKey = new Gost3410PublicKey();
            }
            else if (algId == GostConstants.CALG_GR3410_12_256)
            {
                publicKey = new Gost3410_2012_256PublicKey();
            }
            else if (algId == GostConstants.CALG_GR3410_12_512)
            {
                publicKey = new Gost3410_2012_512PublicKey();
            }
            else
            {
                throw new CryptographicException(
                        SR.Cryptography_CSP_WrongKeySpec);
            }
            publicKey.Decode(asnDecoder);

            _publicKey = publicKey.Value;
        }

        /// <summary>
        /// OID параметров хеширования.
        /// </summary>
        internal string _digestParamSet;
        /// <summary>
        /// Необязательный OID параметров шифрования.
        /// </summary>
        internal string _encryptionParamSet;
        /// <summary>
        /// OID параметров подписи и DH.
        /// </summary>
        internal string _publicKeyParamSet;
        /// <summary>
        /// Открытый ключ.
        /// </summary>
        internal byte[] _publicKey;
        /// <summary>
        /// Секретный ключ.
        /// </summary>
        internal byte[] _privateKey;
    }
}
