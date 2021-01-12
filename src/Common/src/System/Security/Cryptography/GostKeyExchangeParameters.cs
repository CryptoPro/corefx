// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
    /// <summary>
    /// Параметры алгоритма цифровой подписи ГОСТ Р 34.10 и алгоритма формирования общего секретного ключа, включая открытый ключ.
    /// </summary>
    public sealed class GostKeyExchangeParameters
    {
        public GostKeyExchangeParameters()
        {
        }

        public GostKeyExchangeParameters(GostKeyExchangeParameters parameters)
        {
            DigestParamSet = parameters.DigestParamSet;
            PublicKeyParamSet = parameters.PublicKeyParamSet;
            EncryptionParamSet = parameters.EncryptionParamSet;
            PublicKey = parameters.PublicKey;
            PrivateKey = parameters.PrivateKey;
        }


        /// <summary>
        /// Идентификатор OID параметров хэширования.
        /// </summary>
        public string DigestParamSet;

        /// <summary>
        /// Идентификатор OID параметров открытого ключа.
        /// </summary>
        public string PublicKeyParamSet;

        /// <summary>
        /// Идентификатор OID параметров шифрования.
        /// </summary>
        public string EncryptionParamSet;

        /// <summary>
        /// Открытый ключ.
        /// </summary>
        public byte[] PublicKey;

        /// <summary>
        /// Закрытый ключ.
        /// </summary>
        public byte[] PrivateKey;


        public void DecodeParameters(byte[] data)
        {
            if (data == null)
            {
                throw new ArgumentNullException(nameof(data));
            }

            var asnDecoder = new Asn1BerDecodeBuffer(data);
            var publicKeyParameters = new GostR3410_2001_PublicKeyParameters();
            publicKeyParameters.Decode(asnDecoder);

            DigestParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.DigestParamSet);
            PublicKeyParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.PublicKeyParamSet);
            EncryptionParamSet = Asn1ObjectIdentifier.ToOidString(publicKeyParameters.EncryptionParamSet);
        }


        public byte[] EncodeParameters()
        {
            byte[] data;

            var publicKeyParameters = new GostR3410_2001_PublicKeyParameters();

            publicKeyParameters.DigestParamSet = Asn1ObjectIdentifier.FromOidString(DigestParamSet);
            publicKeyParameters.PublicKeyParamSet = Asn1ObjectIdentifier.FromOidString(PublicKeyParamSet);
            publicKeyParameters.EncryptionParamSet = CreateEncryptionParamSet(EncryptionParamSet);

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

            var asnDecoder = new Asn1BerDecodeBuffer(data);

            Asn1OctetString publicKey;
            if (algId == GostConstants.CALG_GR3410EL)
            {
                publicKey = new GostR3410_PublicKey();
                publicKey.Decode(asnDecoder);
            }
            else if (algId == GostConstants.CALG_GR3410_12_256)
            {
                publicKey = new GostR3410_2012_256_PublicKey();
                publicKey.Decode(asnDecoder);
            }
            else if (algId == GostConstants.CALG_GR3410_12_512)
            {
                publicKey = new GostR3410_2012_512_PublicKey();
                publicKey.Decode(asnDecoder);
            }
            else
            {
                throw new CryptographicException(
                    SR.Cryptography_CSP_WrongKeySpec);
            }
            PublicKey = publicKey.Value;
        }

        internal static Gost28147_89_ParamSet CreateEncryptionParamSet(string value)
        {
            return (value != null) ? new Gost28147_89_ParamSet(Asn1ObjectIdentifier.FromOidString(value).Value) : null;
        }

        public static byte[] EncodePublicBlob(GostKeyExchangeParameters publicKeyParameters, int algId)
        {
            if (publicKeyParameters == null)
            {
                throw new ArgumentNullException(nameof(publicKeyParameters));
            }

            int keySize;

            if (algId == GostConstants.CALG_GR3410EL)
            {
                keySize = GostConstants.GOST_3410EL_SIZE;
            }
            else if (algId == GostConstants.CALG_GR3410_12_256)
            {
                keySize = GostConstants.GOST3410_2012_256KEY_SIZE;
            }
            else if (algId == GostConstants.CALG_GR3410_12_512)
            {
                keySize = GostConstants.GOST3410_2012_512KEY_SIZE;
            }
            else
            {
                throw new CryptographicException(
                        SR.Cryptography_CSP_WrongKeySpec);
            }                

            var encodeKeyParameters = publicKeyParameters.EncodeParameters();
            var importedKeyBytes = new byte[(encodeKeyParameters.Length + 16) + publicKeyParameters.PublicKey.Length];
            importedKeyBytes[0] = 6;
            importedKeyBytes[1] = 32;
            Array.Copy(BitConverter.GetBytes(algId), 0, importedKeyBytes, 4, 4);
            Array.Copy(BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC), 0, importedKeyBytes, 8, 4);
            Array.Copy(BitConverter.GetBytes(keySize), 0, importedKeyBytes, 12, 4);
            Array.Copy(encodeKeyParameters, 0, importedKeyBytes, 16, encodeKeyParameters.Length);
            Array.Copy(publicKeyParameters.PublicKey, 0, importedKeyBytes, encodeKeyParameters.Length + 16, publicKeyParameters.PublicKey.Length);

            return importedKeyBytes;
        }
    }
}
