namespace System.Security.Cryptography
{
    /// <summary>
    /// Класс, содержащий константы, используемые библиотекой 
    /// CryptoPro.Sharpei: имена алгоритмов,
    /// OID-ы, длины ключей, коды ошибок и т.п.
    /// </summary>
    internal static class GostConstants
    {
        //// dwFlags definitions for CryptAcquireContext
        //internal const uint CRYPT_NEWKEYSET = 0x00000008;
        //internal const uint CRYPT_VERIFYCONTEXT = 0xF0000000;
        //internal const uint CRYPT_MACHINEKEYSET = 0x00000020;
        //internal const uint CRYPT_SILENT = 0x00000040;

        //internal const int HP_HASHVAL = 0x0002;
        //internal const int HP_HASHSTARTVECT = 0x0008;

        //// dwFlag definitions for CryptGenKey
        //internal const int CRYPT_EXPORTABLE = 0x00000001;
        //internal const int CRYPT_ARCHIVABLE = 0x00004000;
        //internal const int CRYPT_USER_PROTECTED = 0x00000002;
        //internal const int CRYPT_PREGEN = 0x00000040;

        /// <summary>
        /// OID алгоритма хэширования ГОСТ Р 34.11-2001
        /// </summary>
        internal const string OID_CP_GOST_R3411 = "1.2.643.2.2.9";
        /// <summary>
        /// OID алгоритма хэширования ГОСТ Р 34.11-2012 256
        /// </summary>
        internal const string OID_CP_GOST_R3411_12_256 = "1.2.643.7.1.1.2.2";
        /// <summary>
        /// OID алгоритма хэширования ГОСТ Р 34.11-2012 512
        /// </summary>
        internal const string OID_CP_GOST_R3411_12_512 = "1.2.643.7.1.1.2.3";
        /// <summary>
        /// OID алгоритма открытого ключа/цифровой подписи ГОСТ Р 34.10-2001
        /// </summary>
        internal const string OID_CP_GOST_R3410EL = "1.2.643.2.2.19";
        /// <summary>
        /// OID алгоритма цифровой подписи ГОСТ Р 34.10-2001 (используется как SignatureAlgorithm в сертификате)
        /// </summary>
        internal const string OID_CP_GOST_R3411_R3410EL = "1.2.643.2.2.3";
        /// <summary>
        /// OID алгоритма открытого ключа/цифровой подписи ГОСТ Р 34.10-2012 256
        /// </summary>
        internal const string OID_CP_GOST_R3410_12_256 = "1.2.643.7.1.1.1.1";
        /// <summary>
        /// OID алгоритма цифровой подписи ГОСТ Р 34.10-2012 256 (используется как SignatureAlgorithm в сертификате)
        /// </summary>
        internal const string OID_CP_GOST_R3411_12_256_R3410 = "1.2.643.7.1.1.3.2";
        /// <summary>
        /// OID алгоритма открытого ключа/цифровой подписи ГОСТ Р 34.10-2012 512
        /// </summary>
        internal const string OID_CP_GOST_R3410_12_512 = "1.2.643.7.1.1.1.2";
        /// <summary>
        /// OID алгоритма цифровой подписи ГОСТ Р 34.10-2012 512 (используется как SignatureAlgorithm в сертификате)
        /// </summary>
        internal const string OID_CP_GOST_R3411_12_512_R3410 = "1.2.643.7.1.1.3.3";
        /// <summary>
        /// OID параметров шифрования по умолчанию.
        /// </summary>
        internal const string OID_CipherVerbaO = "1.2.643.2.2.31.1";
        /// <summary>
        /// OID параметров шифрования по умолчанию.
        /// </summary>
        internal const string OID_Gost28147 = "1.2.643.2.2.21";

        /// <summary>
        /// Алгоритм подписи ГОСТ Р 34.10-2001 + хеширования.
        /// </summary>
        internal const string XmlSignatureAlgorithm2001 =
            "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102001-gostr3411";

        /// <summary>
        /// Алгоритм подписи ГОСТ Р 34.10-2012 + хеширования. 256 бит
        /// </summary>
        internal const string XmlSignatureAlgorithm2012_256 =
            "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-256";

        /// <summary>
        /// Алгоритм подписи ГОСТ Р 34.10-2012 + хеширования. 512 бит
        /// </summary>
        internal const string XmlSignatureAlgorithm2012_512 =
            "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gostr34102012-gostr34112012-512";

        /// <summary>
        /// Алгоритм транспорта на ГОСТ Р 34.10-2001 
        /// </summary>
        internal const string XmlKeyExchangeAlgorithmTransport2001 =
            "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2001";

        /// <summary>
        /// Алгоритм транспорта на ГОСТ Р 34.10-2012 256 
        /// </summary>
        internal const string XmlKeyExchangeAlgorithmTransport2012_256 =
            "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-256";

        /// <summary>
        /// Алгоритм транспорта на ГОСТ Р 34.10-2012 512 
        /// </summary>
        internal const string XmlKeyExchangeAlgorithmTransport2012_512 =
            "urn:ietf:params:xml:ns:cpxmlsec:algorithms:transport-gost2012-512";

        /// <summary>
        /// Алгоримтм шифрования ГОСТ 28147
        /// </summary>
        internal const string XmlEncGost28147Url = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:gost28147";

        /// <summary>
        /// Алгоритм экспорта КриптоПро
        /// </summary>
        internal const string XmlEncGostCryptoProKeyWrapUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:kw-cp";

        /// <summary>
        /// Алгоритм экпорта КриптоПро 12
        /// </summary>
        internal const string XmlEncGostCryptoPro12KeyWrapUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:kw-cp12";

        /// <summary>
        /// Алгоритм экспорта ГОСТ
        /// </summary>
        internal const string XmlEncGost28147KeyWrapUrl = "urn:ietf:params:xml:ns:cpxmlsec:algorithms:kw-gost";

        // Error codes
        internal const int NTE_BAD_HASH = -2146893822; // 0x80090002L;
        internal const int NTE_BAD_DATA = -2146893819; // 0x80090005
        internal const int NTE_BAD_ALGID = -2146893816; // 0x80090008
        internal const int NTE_NO_KEY = -2146893811; // 0x8009000DL
        internal const int NTE_BAD_KEYSET = -2146893802; // 0x80090016L
        internal const int NTE_BAD_KEYSET_PARAM = -2146893793; // 0x8009001FL
        internal const int NTE_KEYSET_NOT_DEF = -2146893799; // 0x80090019L
        internal const int SCARD_W_CANCELLED_BY_USER = -2146434962; // 0x8010006EL
        internal const int SCARD_E_NO_SUCH_CERTIFICATE = -2146435028; // 0x8010002CL
        internal const int CRYPT_E_NOT_FOUND = -2146885628; //0x80092004

        // algorithm identifier definitions
        internal const int CALG_MD5 = 0x8003;
        internal const int CALG_SHA1 = 0x8004;
        internal const int CALG_SHA256 = 0x800C;
        internal const int CALG_SHA384 = 0x800D;
        internal const int CALG_SHA512 = 0x800E;
        internal const int CALG_RSA_KEYX = 0xa400;
        internal const int CALG_RSA_SIGN = 0x2400;
        internal const int CALG_DSS_SIGN = 0x2200;

        internal const int CALG_DH_EL_EPHEM = (int)0xaa25;
        internal const int CALG_DH_EL_SF = (int)0xaa24;
        internal const int ALG_SID_DH_GR3410_12_256_EPHEM = (int)0xaa47;
        internal const int CALG_DH_GR3410_12_256_SF = (int)0xaa46;
        internal const int ALG_SID_DH_GR3410_12_512_EPHEM = (int)0xaa43;
        internal const int CALG_DH_GR3410_12_512_SF = (int)0xaa42;
        internal const int CALG_GR3411 = (int)0x801e;
        internal const int CALG_GR3411_2012_256 = (int)0x8021;
        internal const int CALG_GR3411_2012_512 = (int)0x8022;
        internal const int CALG_GR3410EL = 0x2e23;
        internal const int CALG_GR3410_12_256 = 0x2e49;
        internal const int CALG_GR3410_12_512 = 0x2e3d;
        internal const int CALG_G28147 = 0x661e;
        internal const int CALG_G28147_IMIT = 0x801f;
        internal const int CALG_SYMMETRIC_512 = 0x6622;
        internal const int CALG_GENERIC_SECRET = 0x6615;
        internal const int CALG_AES_128 = 0x660e;
        internal const int CALG_SIMPLE_EXPORT = 0x6620;
        internal const int CALG_PRO_EXPORT = 0x661f;
        internal const int CALG_PRO12_EXPORT = 0x6621;
        internal const int CALG_GR3411_HMAC = 0x8027;
        internal const int CALG_GR3411_2012_256_HMAC = 0x8034;
        internal const int CALG_GR3411_2012_512_HMAC = 0x8035;
        internal const int CALG_HMAC = 0x8009;

        // CryptGetProvParam/CryptSetProvParam dwParam
        internal const int PP_CLIENT_HWND = 1;
        internal const int PP_ENUMALGS_EX = 22;
        internal const int PP_KEYEXCHANGE_PIN = 32;
        internal const int PP_SIGNATURE_PIN = 33;
        internal const int PP_SELECT_CONTAINER = 110;
        internal const int PP_DELETE_KEYSET = 125;
        internal const int PP_HCRYPTPROV = 109;

        internal const int CRYPT_FIRST = 1;
        internal const int CRYPT_FQCN = 16; // 0x10

        // CryptGetKeyParam/CryptSetKeyParam dwParam
        internal const int KP_IV = 1;
        internal const int KP_SV = KP_IV;
        internal const int KP_PADDING = 3;
        internal const int KP_MODE = 4;
        internal const int KP_ALGID = 7;
        internal const int KP_KEYLEN = 9;
        internal const int KP_X = 14;
        internal const int KP_CERTIFICATE = 26;
        internal const int KP_CIPHEROID = 104;
        internal const int KP_HASHOID = 103;
        internal const int KP_DHOID = 106;

        // CertGetCertificateContextProperty/CertSetCertificateContextProperty
        internal const int CERT_KEY_CONTEXT_PROP_ID = 5;

        // exported key blob definitions
        internal const int PUBLICKEYBLOB = 0x6;
        internal const int PRIVATEKEYBLOB = 0x7;
        internal const int SIMPLEBLOB = 0x1;

        // exported key blob flags definitions
        internal const int CRYPT_PUBLICCOMPRESS = 0x00000800;

        //
        internal const int CP_CRYPT_CALCULATE_PUBLIC_KEY = 0x80;

        // Provider types
        internal const int PROV_GOST_2001_DH = 75;
        internal const int PROV_GOST_2012_256 = 80;
        internal const int PROV_GOST_2012_512 = 81;

        // Текущий номер версии blob
        internal const byte CUR_BLOB_VERSION = 0x2;
        internal const byte CSP_CUR_BLOB_VERSION = 0x20;

        // cryptographic sizes
        internal const int GOST_3410EL_SIZE = 512;
        internal const int GOST3410_2012_256KEY_SIZE = 512;
        internal const int GOST3410_2012_512KEY_SIZE = 1024;
        internal const int SEANCE_VECTOR_LEN = 8;
        internal const int G28147_KEYLEN = 32;
        internal const int EXPORT_IMIT_SIZE = 4;
        internal const int GOST3411_SIZE = 256;
        internal const int GOST3411_2012_256_SIZE = 256;
        internal const int GOST3411_2012_512_SIZE = 512;

        // Magic BLOB
        internal const int GR3410_1_MAGIC = 0x3147414D;
        internal const int SIMPLEBLOB_MAGIC = 0x374A51FD;

        // Padding mode используемый в WinCrypt
        internal const int WINCRYPT_PADDING_ZERO = 3;

        // При любых изменениях синхронизировать с cpXml!
        internal const string TagKeyValue2001 = "GOSTKeyValue";
        internal const string TagPublicKeyParameters = "PublicKeyParameters";
        internal const string TagPublicKeyParamSet = "publicKeyParamSet";
        internal const string TagDigestParamSet = "digestParamSet";
        internal const string TagEncryptionParamSet = "encryptionParamSet";
        internal const string TagPublicKey = "PublicKey";
        internal const string TagPrivateKey = "PrivateKey";

        // string algorithm names
        internal const string GOST3411_STRING = "Gost3411";
        internal const string GOST3411_2012_256STRING = "Gost3411_2012_256";
        internal const string GOST3411_2012_512STRING = "Gost3411_2012_512";

        internal const string GOST3410_STRING = "Gost3410";
        internal const string GOST3410_2012_256STRING = "Gost3410_2012_256";
        internal const string GOST3410_2012_512STRING = "Gost3410_2012_512";

        /// <summary>
        /// Базовый namespace XMLdsig.
        /// </summary>
        internal const string XmlDsigNamespace = "http://www.w3.org/2000/09/xmldsig#";
        /// <summary>
        /// Базовый namespace для XMLenc.
        /// </summary>
        internal const string XmlEncNamespace = "http://www.w3.org/2001/04/xmlenc#";
    }
}
