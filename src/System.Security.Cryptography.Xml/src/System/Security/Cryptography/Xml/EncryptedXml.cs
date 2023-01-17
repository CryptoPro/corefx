// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Collections;
using System.IO;
using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Policy;
using System.Text;
using System.Xml;

namespace System.Security.Cryptography.Xml
{
    public class EncryptedXml
    {
        //
        // public constant Url identifiers used within the XML Encryption classes
        //

        public const string XmlEncNamespaceUrl = "http://www.w3.org/2001/04/xmlenc#";
        public const string XmlEncElementUrl = "http://www.w3.org/2001/04/xmlenc#Element";
        public const string XmlEncElementContentUrl = "http://www.w3.org/2001/04/xmlenc#Content";
        public const string XmlEncEncryptedKeyUrl = "http://www.w3.org/2001/04/xmlenc#EncryptedKey";

        //
        // Symmetric Block Encryption
        //

        public const string XmlEncDESUrl = "http://www.w3.org/2001/04/xmlenc#des-cbc";
        public const string XmlEncTripleDESUrl = "http://www.w3.org/2001/04/xmlenc#tripledes-cbc";
        public const string XmlEncAES128Url = "http://www.w3.org/2001/04/xmlenc#aes128-cbc";
        public const string XmlEncAES256Url = "http://www.w3.org/2001/04/xmlenc#aes256-cbc";
        public const string XmlEncAES192Url = "http://www.w3.org/2001/04/xmlenc#aes192-cbc";
        // begin: gost
        public const string XmlEncGost28147Url = GostConstants.XmlEncGost28147Url;
        // end: gost

        //
        // Key Transport
        //

        public const string XmlEncRSA15Url = "http://www.w3.org/2001/04/xmlenc#rsa-1_5";
        public const string XmlEncRSAOAEPUrl = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p";
        public const string XmlEncGostKeyTransportUrl = GostConstants.XmlKeyExchangeAlgorithmTransport2001;
        public const string XmlEncGost2012_256KeyTransportUrl = GostConstants.XmlKeyExchangeAlgorithmTransport2012_256;
        public const string XmlEncGost2012_512KeyTransportUrl = GostConstants.XmlKeyExchangeAlgorithmTransport2012_512;

        //
        // Symmetric Key Wrap
        //

        public const string XmlEncTripleDESKeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-tripledes";
        public const string XmlEncAES128KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes128";
        public const string XmlEncAES256KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes256";
        public const string XmlEncAES192KeyWrapUrl = "http://www.w3.org/2001/04/xmlenc#kw-aes192";
        // begin: gost
        public const string XmlEncGostCryptoProKeyWrapUrl = GostConstants.XmlEncGost28147KeyWrapUrl;
        public const string XmlEncGostCryptoPro12KeyWrapUrl = GostConstants.XmlEncGostCryptoPro12KeyWrapUrl;
        public const string XmlEncGost28147KeyWrapUrl = GostConstants.XmlEncGost28147KeyWrapUrl;
        // end: gost

        //
        // Message Digest
        //

        public const string XmlEncSHA256Url = "http://www.w3.org/2001/04/xmlenc#sha256";
        public const string XmlEncSHA512Url = "http://www.w3.org/2001/04/xmlenc#sha512";

        //
        // private members
        //

        private XmlDocument _document;
        private Evidence _evidence;
        private XmlResolver _xmlResolver;
        // hash table defining the key name mapping
        private const int _capacity = 4; // 4 is a reasonable capacity for
                                          // the key name mapping hash table
        private Hashtable _keyNameMapping;
        private PaddingMode _padding;
        private CipherMode _mode;
        private Encoding _encoding;
        private string _recipient;
        private int _xmlDsigSearchDepthCounter = 0;
        private int _xmlDsigSearchDepth;

        //
        // public constructors
        //
        public EncryptedXml() : this(new XmlDocument()) { }

        public EncryptedXml(XmlDocument document) : this(document, null) { }

        public EncryptedXml(XmlDocument document, Evidence evidence)
        {
            _document = document;
            _evidence = evidence;
            _xmlResolver = null;
            // set the default padding to ISO-10126
            _padding = PaddingMode.ISO10126;
            // set the default cipher mode to CBC
            _mode = CipherMode.CBC;
            // By default the encoding is going to be UTF8
            _encoding = Encoding.UTF8;
            _keyNameMapping = new Hashtable(_capacity);
            _xmlDsigSearchDepth = Utils.XmlDsigSearchDepth;
        }

        /// <summary>
        /// This method validates the _xmlDsigSearchDepthCounter counter
        /// if the counter is over the limit defined by admin or developer.
        /// </summary>
        /// <returns>returns true if the limit has reached otherwise false</returns>
        private bool IsOverXmlDsigRecursionLimit()
        {
            if (_xmlDsigSearchDepthCounter > XmlDSigSearchDepth)
            {
                return true;
            }
            return false;
        }

        /// <summary>
        /// Gets / Sets the max limit for recursive search of encryption key in signed XML
        /// </summary>
        public int XmlDSigSearchDepth
        {
            get
            {
                return _xmlDsigSearchDepth;
            }
            set
            {
                _xmlDsigSearchDepth = value;
            }
        }

        // The evidence of the document being loaded: will be used to resolve external URIs
        public Evidence DocumentEvidence
        {
            get { return _evidence; }
            set { _evidence = value; }
        }

        // The resolver to use for external entities
        public XmlResolver Resolver
        {
            get { return _xmlResolver; }
            set { _xmlResolver = value; }
        }

        // The padding to be used. XML Encryption uses ISO 10126
        // but it's nice to provide a way to extend this to include other forms of paddings
        public PaddingMode Padding
        {
            get { return _padding; }
            set { _padding = value; }
        }

        // The cipher mode to be used. XML Encryption uses CBC padding
        // but it's nice to provide a way to extend this to include other cipher modes
        public CipherMode Mode
        {
            get { return _mode; }
            set { _mode = value; }
        }

        // The encoding of the XML document
        public Encoding Encoding
        {
            get { return _encoding; }
            set { _encoding = value; }
        }

        // This is used to specify the EncryptedKey elements that should be considered
        // when an EncyptedData references an EncryptedKey using a CarriedKeyName and Recipient
        public string Recipient
        {
            get
            {
                // an unspecified value for an XmlAttribute is string.Empty
                if (_recipient == null)
                    _recipient = string.Empty;
                return _recipient;
            }
            set { _recipient = value; }
        }

        //
        // private methods
        //

        private byte[] GetCipherValue(CipherData cipherData)
        {
            if (cipherData == null)
                throw new ArgumentNullException(nameof(cipherData));

            Stream inputStream = null;

            if (cipherData.CipherValue != null)
            {
                return cipherData.CipherValue;
            }
            else if (cipherData.CipherReference != null)
            {
                if (cipherData.CipherReference.CipherValue != null)
                    return cipherData.CipherReference.CipherValue;
                Stream decInputStream = null;
                if (cipherData.CipherReference.Uri == null)
                {
                    throw new CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                }
                // See if the CipherReference is a local URI
                if (cipherData.CipherReference.Uri.Length == 0)
                {
                    // self referenced Uri
                    string baseUri = (_document == null ? null : _document.BaseURI);
                    TransformChain tc = cipherData.CipherReference.TransformChain;
                    if (tc == null)
                    {
                        throw new CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                    }
                    decInputStream = tc.TransformToOctetStream(_document, _xmlResolver, baseUri);
                }
                else if (cipherData.CipherReference.Uri[0] == '#')
                {
                    string idref = Utils.ExtractIdFromLocalUri(cipherData.CipherReference.Uri);
                    // Serialize 
                    XmlElement idElem = GetIdElement(_document, idref);
                    if (idElem == null || idElem.OuterXml == null)
                    {
                        throw new CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                    }
                    inputStream = new MemoryStream(_encoding.GetBytes(idElem.OuterXml));
                    string baseUri = (_document == null ? null : _document.BaseURI);
                    TransformChain tc = cipherData.CipherReference.TransformChain;
                    if (tc == null)
                    {
                        throw new CryptographicException(SR.Cryptography_Xml_UriNotSupported);
                    }
                    decInputStream = tc.TransformToOctetStream(inputStream, _xmlResolver, baseUri);
                }
                else
                {
                    throw new CryptographicException(SR.Cryptography_Xml_UriNotResolved, cipherData.CipherReference.Uri);
                }
                // read the output stream into a memory stream
                byte[] cipherValue = null;
                using (MemoryStream ms = new MemoryStream())
                {
                    Utils.Pump(decInputStream, ms);
                    cipherValue = ms.ToArray();
                    // Close the stream and return
                    if (inputStream != null)
                        inputStream.Close();
                    decInputStream.Close();
                }

                // cache the cipher value for Perf reasons in case we call this routine twice
                cipherData.CipherReference.CipherValue = cipherValue;
                return cipherValue;
            }

            // Throw a CryptographicException if we were unable to retrieve the cipher data.
            throw new CryptographicException(SR.Cryptography_Xml_MissingCipherData);
        }

        //
        // public virtual methods
        //

        // This describes how the application wants to associate id references to elements
        public virtual XmlElement GetIdElement(XmlDocument document, string idValue)
        {
            return SignedXml.DefaultGetIdElement(document, idValue);
        }

        // default behaviour is to look for the IV in the CipherValue
        public virtual byte[] GetDecryptionIV(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));

            int initBytesSize = 0;
            // If the Uri is not provided by the application, try to get it from the EncryptionMethod
            if (symmetricAlgorithmUri == null)
            {
                if (encryptedData.EncryptionMethod == null)
                    throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
            }
            switch (symmetricAlgorithmUri)
            {
                case EncryptedXml.XmlEncDESUrl:
                case EncryptedXml.XmlEncTripleDESUrl:
                // begin: gost
                case EncryptedXml.XmlEncGost28147Url:
                // end: gost
                    initBytesSize = 8;
                    break;
                case EncryptedXml.XmlEncAES128Url:
                case EncryptedXml.XmlEncAES192Url:
                case EncryptedXml.XmlEncAES256Url:
                    initBytesSize = 16;
                    break;
                default:
                    // The Uri is not supported.
                    throw new CryptographicException(SR.Cryptography_Xml_UriNotSupported);
            }
            byte[] IV = new byte[initBytesSize];
            byte[] cipherValue = GetCipherValue(encryptedData.CipherData);
            Buffer.BlockCopy(cipherValue, 0, IV, 0, IV.Length);
            return IV;
        }

        // default behaviour is to look for keys defined by an EncryptedKey clause
        // either directly or through a KeyInfoRetrievalMethod, and key names in the key mapping
        public virtual SymmetricAlgorithm GetDecryptionKey(EncryptedData encryptedData, string symmetricAlgorithmUri)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));

            if (encryptedData.KeyInfo == null)
                return null;
            IEnumerator keyInfoEnum = encryptedData.KeyInfo.GetEnumerator();
            KeyInfoRetrievalMethod kiRetrievalMethod;
            KeyInfoName kiName;
            KeyInfoEncryptedKey kiEncKey;
            EncryptedKey ek = null;

            while (keyInfoEnum.MoveNext())
            {
                kiName = keyInfoEnum.Current as KeyInfoName;
                if (kiName != null)
                {
                    // Get the decryption key from the key mapping
                    string keyName = kiName.Value;
                    if ((SymmetricAlgorithm)_keyNameMapping[keyName] != null)
                        return (SymmetricAlgorithm)_keyNameMapping[keyName];
                    // try to get it from a CarriedKeyName
                    XmlNamespaceManager nsm = new XmlNamespaceManager(_document.NameTable);
                    nsm.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);
                    XmlNodeList encryptedKeyList = _document.SelectNodes("//enc:EncryptedKey", nsm);
                    if (encryptedKeyList != null)
                    {
                        foreach (XmlNode encryptedKeyNode in encryptedKeyList)
                        {
                            XmlElement encryptedKeyElement = encryptedKeyNode as XmlElement;
                            EncryptedKey ek1 = new EncryptedKey();
                            ek1.LoadXml(encryptedKeyElement);
                            if (ek1.CarriedKeyName == keyName && ek1.Recipient == Recipient)
                            {
                                ek = ek1;
                                break;
                            }
                        }
                    }
                    break;
                }
                kiRetrievalMethod = keyInfoEnum.Current as KeyInfoRetrievalMethod;
                if (kiRetrievalMethod != null)
                {
                    string idref = Utils.ExtractIdFromLocalUri(kiRetrievalMethod.Uri);
                    ek = new EncryptedKey();
                    ek.LoadXml(GetIdElement(_document, idref));
                    break;
                }
                kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;
                if (kiEncKey != null)
                {
                    ek = kiEncKey.EncryptedKey;
                    break;
                }
            }

            // if we have an EncryptedKey, decrypt to get the symmetric key
            if (ek != null)
            {
                // now process the EncryptedKey, loop recursively 
                // If the Uri is not provided by the application, try to get it from the EncryptionMethod
                if (symmetricAlgorithmUri == null)
                {
                    if (encryptedData.EncryptionMethod == null)
                        throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                    symmetricAlgorithmUri = encryptedData.EncryptionMethod.KeyAlgorithm;
                }
                // begin: gost
                SymmetricAlgorithm symAlg;
                if (symmetricAlgorithmUri == EncryptedXml.XmlEncGostKeyTransportUrl ||
                      symmetricAlgorithmUri == EncryptedXml.XmlEncGost2012_256KeyTransportUrl ||
                      symmetricAlgorithmUri == EncryptedXml.XmlEncGost2012_512KeyTransportUrl ||
                      symmetricAlgorithmUri == EncryptedXml.XmlEncGost28147Url)
                {
                    symAlg = DecryptEncryptedKey(
                        ek,
                        symmetricAlgorithmUri);
                }
                else
                {
                    // end: gost
                    byte[] key = DecryptEncryptedKey(ek);
                    if (key == null)
                        throw new CryptographicException(SR.Cryptography_Xml_MissingDecryptionKey);

                    symAlg = CryptoHelpers.CreateFromName<SymmetricAlgorithm>(symmetricAlgorithmUri);

                    if (symAlg == null)
                    {
                        throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                    }
                    symAlg.Key = key;
                }
                return symAlg;
            }
            return null;
        }

        // Try to decrypt the EncryptedKey given the key mapping
        public virtual byte[] DecryptEncryptedKey(EncryptedKey encryptedKey)
        {
            if (encryptedKey == null)
                throw new ArgumentNullException(nameof(encryptedKey));
            if (encryptedKey.KeyInfo == null)
                return null;

            IEnumerator keyInfoEnum = encryptedKey.KeyInfo.GetEnumerator();
            KeyInfoName kiName;
            KeyInfoX509Data kiX509Data;
            KeyInfoRetrievalMethod kiRetrievalMethod;
            KeyInfoEncryptedKey kiEncKey;
            EncryptedKey ek = null;
            bool fOAEP = false;

            while (keyInfoEnum.MoveNext())
            {
                kiName = keyInfoEnum.Current as KeyInfoName;
                if (kiName != null)
                {
                    // Get the decryption key from the key mapping
                    string keyName = kiName.Value;
                    object kek = _keyNameMapping[keyName];
                    if (kek != null)
                    {
                        if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                        {
                            throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                        }
                        // kek is either a SymmetricAlgorithm or an RSA key, otherwise, we wouldn't be able to insert it in the hash table
                        if (kek is SymmetricAlgorithm)
                        {
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, (SymmetricAlgorithm)kek);
                        }

                        // kek is an RSA key: get fOAEP from the algorithm, default to false
                        fOAEP = (encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl);
                        return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, (RSA)kek, fOAEP);
                    }
                    break;
                }
                kiX509Data = keyInfoEnum.Current as KeyInfoX509Data;
                if (kiX509Data != null)
                {
                    X509Certificate2Collection collection = Utils.BuildBagOfCerts(kiX509Data, CertUsageType.Decryption);
                    foreach (X509Certificate2 certificate in collection)
                    {
                        using (RSA privateKey = certificate.GetRSAPrivateKey())
                        {
                            if (privateKey != null)
                            {
                                if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                                {
                                    throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                                }
                                fOAEP = (encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl);
                                return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, privateKey, fOAEP);
                            }
                        }
                    }
                    break;
                }
                kiRetrievalMethod = keyInfoEnum.Current as KeyInfoRetrievalMethod;
                if (kiRetrievalMethod != null)
                {
                    string idref = Utils.ExtractIdFromLocalUri(kiRetrievalMethod.Uri);
                    ek = new EncryptedKey();
                    ek.LoadXml(GetIdElement(_document, idref));
                    try
                    {
                        //Following checks if XML dsig processing is in loop and within the limit defined by machine
                        // admin or developer. Once the recursion depth crosses the defined limit it will throw exception.
                        _xmlDsigSearchDepthCounter++;
                        if (IsOverXmlDsigRecursionLimit())
                        {
                            //Throw exception once recursion limit is hit. 
                            throw new CryptoSignedXmlRecursionException();
                        }
                        else
                        {
                            return DecryptEncryptedKey(ek);
                        }
                    }
                    finally
                    {
                        _xmlDsigSearchDepthCounter--;
                    }
                }
                kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;
                if (kiEncKey != null)
                {
                    ek = kiEncKey.EncryptedKey;
                    // recursively process EncryptedKey elements
                    byte[] encryptionKey = DecryptEncryptedKey(ek);
                    if (encryptionKey != null)
                    {
                        // this is a symmetric algorithm for sure
                        SymmetricAlgorithm symAlg = CryptoHelpers.CreateFromName<SymmetricAlgorithm>(encryptedKey.EncryptionMethod.KeyAlgorithm);
                        if (symAlg == null)
                        {
                            throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                        }
                        symAlg.Key = encryptionKey;
                        if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                        {
                            throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                        }
                        symAlg.Key = encryptionKey;
                        return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, symAlg);
                    }
                }
            }
            return null;
        }

        // begin: gost
        /// <summary>
        /// Импорт зашифрованного ключа.
        /// </summary>
        /// 
        /// <param name="encryptedKey">Зашифрованный ключ.</param>
        /// <param name="symmetricAlgorithmUri">Алгоритм экспортируемого
        /// ключа.</param>
        /// 
        /// <returns>Ключ в виде симметричного алгоритма</returns>
        /// 
        /// <argnull name="encryptedKey" />
        /// 
        /// <intdoc>
        /// <para>Функция не произовдит излишних преобразований из key
        /// в массив байтов, поэтому изменен прототип и изменено имя.</para>
        /// </intdoc>
        internal SymmetricAlgorithm DecryptEncryptedKey(
            EncryptedKey encryptedKey, string symmetricAlgorithmUri)
        {
            if (encryptedKey == null)
                throw new ArgumentNullException(nameof(encryptedKey));
            if (encryptedKey.KeyInfo == null)
                return null;

            IEnumerator keyInfoEnum = encryptedKey.KeyInfo.GetEnumerator();
            KeyInfoName kiName;
            KeyInfoX509Data kiX509Data;
            KeyInfoRetrievalMethod kiRetrievalMethod;
            KeyInfoEncryptedKey kiEncKey;
            EncryptedKey ek = null;
            bool fOAEP = false;

            while (keyInfoEnum.MoveNext())
            {
                kiName = keyInfoEnum.Current as KeyInfoName;
                if (kiName != null)
                {
                    // Get the decryption key from the key mapping
                    string keyName = kiName.Value;
                    object kek = _keyNameMapping[keyName];
                    if (kek != null)
                    {
                        if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                        {
                            throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                        }
                        // kek is either a SymmetricAlgorithm or an RSA key, otherwise, we wouldn't be able to insert it in the hash table
                        if (kek is SymmetricAlgorithm)
                        {
                            return EncryptedXml.DecryptKey(
                                encryptedKey.CipherData.CipherValue, 
                                (SymmetricAlgorithm)kek, 
                                symmetricAlgorithmUri, 
                                encryptedKey.EncryptionMethod.KeyAlgorithm);
                        }

                        // kek is an RSA key: get fOAEP from the algorithm, default to false
                        if (kek is RSA rsa)
                        {
                            fOAEP = (encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl);
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, rsa, fOAEP, symmetricAlgorithmUri);
                        }
                        // Экспорт симметричного на ГОСТ 2001.
                        if (kek is Gost3410 gost)
                        {
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, gost, symmetricAlgorithmUri);
                        }
                        // Экспорт симметричного на ГОСТ 2012 256.
                        if (kek is Gost3410_2012_256 gost_2012_256)
                        {
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, gost_2012_256, symmetricAlgorithmUri);
                        }
                        // Экспорт симметричного на ГОСТ 2012 512.
                        if (kek is Gost3410_2012_512 gost_2012_512)
                        {
                            return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, gost_2012_512, symmetricAlgorithmUri);
                        }
                    }
                    break;
                }
                kiX509Data = keyInfoEnum.Current as KeyInfoX509Data;
                if (kiX509Data != null)
                {
                    X509Certificate2Collection collection = Utils.BuildBagOfCerts(kiX509Data, CertUsageType.Decryption);
                    foreach (X509Certificate2 certificate in collection)
                    {
                        using (var privateKey = certificate.PrivateKey)
                        {
                            if (privateKey != null)
                            {
                                if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                                {
                                    throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                                }
                                if (privateKey is RSA rsa)
                                {
                                    fOAEP = (encryptedKey.EncryptionMethod != null && encryptedKey.EncryptionMethod.KeyAlgorithm == EncryptedXml.XmlEncRSAOAEPUrl);
                                    return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, rsa, fOAEP, symmetricAlgorithmUri);
                                }
                                // Экспорт симметричного на ГОСТ 2001.
                                if (privateKey is Gost3410 gost)
                                {
                                    return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, gost, symmetricAlgorithmUri);
                                }
                                // Экспорт симметричного на ГОСТ 2012 256.
                                if (privateKey is Gost3410_2012_256 gost2012_256)
                                {
                                    return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, gost2012_256, symmetricAlgorithmUri);
                                }
                                // Экспорт симметричного на ГОСТ 2012 512.
                                if (privateKey is Gost3410_2012_512 gost2012_512)
                                {
                                    return EncryptedXml.DecryptKey(encryptedKey.CipherData.CipherValue, gost2012_512, symmetricAlgorithmUri);
                                }
                            }
                        }
                    }
                    break;
                }
                kiRetrievalMethod = keyInfoEnum.Current as KeyInfoRetrievalMethod;
                if (kiRetrievalMethod != null)
                {
                    string idref = Utils.ExtractIdFromLocalUri(kiRetrievalMethod.Uri);
                    ek = new EncryptedKey();
                    ek.LoadXml(GetIdElement(_document, idref));
                    try
                    {
                        //Following checks if XML dsig processing is in loop and within the limit defined by machine
                        // admin or developer. Once the recursion depth crosses the defined limit it will throw exception.
                        _xmlDsigSearchDepthCounter++;
                        if (IsOverXmlDsigRecursionLimit())
                        {
                            //Throw exception once recursion limit is hit. 
                            throw new CryptoSignedXmlRecursionException();
                        }
                        else
                        {
                            return DecryptEncryptedKey(ek, symmetricAlgorithmUri);
                        }
                    }
                    finally
                    {
                        _xmlDsigSearchDepthCounter--;
                    }
                }
                kiEncKey = keyInfoEnum.Current as KeyInfoEncryptedKey;
                if (kiEncKey != null)
                {
                    ek = kiEncKey.EncryptedKey;
                    // recursively process EncryptedKey elements
                    SymmetricAlgorithm encryptionKey = DecryptEncryptedKey(ek, symmetricAlgorithmUri);
                    if (encryptionKey != null)
                    {
                        if (encryptedKey.CipherData == null || encryptedKey.CipherData.CipherValue == null)
                        {
                            throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
                        }
                        return EncryptedXml.DecryptKey(
                            encryptedKey.CipherData.CipherValue,
                            encryptionKey,
                            symmetricAlgorithmUri,
                            encryptedKey.EncryptionMethod.KeyAlgorithm);
                    }
                }
            }
            return null;
        }
        // end: gost

        //
        // public methods
        //

        // defines a key name mapping. Default behaviour is to require the key object
        // to be an RSA key or a SymmetricAlgorithm
        public void AddKeyNameMapping(string keyName, object keyObject)
        {
            if (keyName == null)
                throw new ArgumentNullException(nameof(keyName));
            if (keyObject == null)
                throw new ArgumentNullException(nameof(keyObject));

            // begin: gost
            if (!(keyObject is SymmetricAlgorithm) 
                && !(keyObject is RSA)
                && !(keyObject is Gost3410)
                && !(keyObject is Gost3410_2012_256)
                && !(keyObject is Gost3410_2012_512))
                throw new CryptographicException(SR.Cryptography_Xml_NotSupportedCryptographicTransform);
            _keyNameMapping.Add(keyName, keyObject);
            // end: gost
        }

        public void ClearKeyNameMappings()
        {
            _keyNameMapping.Clear();
        }

        // Encrypts the given element with the certificate specified. The certificate is added as
        // an X509Data KeyInfo to an EncryptedKey (AES session key) generated randomly.
        public EncryptedData Encrypt(XmlElement inputElement, X509Certificate2 certificate)
        {
            if (inputElement == null)
                throw new ArgumentNullException(nameof(inputElement));
            if (certificate == null)
                throw new ArgumentNullException(nameof(certificate));

            // begin: gost
            if (!GostConstants.OID_CP_GOST_R3410EL.Equals(
                    certificate.PublicKey.Oid.Value, StringComparison.OrdinalIgnoreCase)
                && !GostConstants.OID_CP_GOST_R3410_12_256.Equals(
                    certificate.PublicKey.Oid.Value, StringComparison.OrdinalIgnoreCase)
                && !GostConstants.OID_CP_GOST_R3410_12_512.Equals(
                    certificate.PublicKey.Oid.Value, StringComparison.OrdinalIgnoreCase))
            {
            // end: gost
                using (RSA rsaPublicKey = certificate.GetRSAPublicKey())
                {
                    if (rsaPublicKey == null)
                        throw new NotSupportedException(SR.NotSupported_KeyAlgorithm);

                    // Create the EncryptedData object, using an AES-256 session key by default.
                    EncryptedData ed = new EncryptedData();
                    ed.Type = EncryptedXml.XmlEncElementUrl;
                    ed.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

                    // Include the certificate in the EncryptedKey KeyInfo.
                    EncryptedKey ek = new EncryptedKey();
                    ek.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncRSA15Url);
                    ek.KeyInfo.AddClause(new KeyInfoX509Data(certificate));

                    // Create a random AES session key and encrypt it with the public key associated with the certificate.
                    RijndaelManaged rijn = new RijndaelManaged();
                    ek.CipherData.CipherValue = EncryptedXml.EncryptKey(rijn.Key, rsaPublicKey, false);

                    // Encrypt the input element with the random session key that we've created above.
                    KeyInfoEncryptedKey kek = new KeyInfoEncryptedKey(ek);
                    ed.KeyInfo.AddClause(kek);
                    ed.CipherData.CipherValue = EncryptData(inputElement, rijn, false);

                    return ed;
                }
            }
            // begin: gost
            // Создаем EncryptedData
            EncryptedData data = new EncryptedData();
            data.Type = "http://www.w3.org/2001/04/xmlenc#Element";
            // Шифруем симметричным алгоритмом, Mode задается ключом
            data.EncryptionMethod = new EncryptionMethod(XmlEncGost28147Url);

            // Создаем EncryptedKey ключ шифрования сообщения
            EncryptedKey xmlKey = new EncryptedKey();
            xmlKey.KeyInfo.AddClause(new KeyInfoX509Data(certificate));

            // Создаем симметричный шифратор
            Gost28147 gost28147 = Gost28147.Create();

            // Вытаскиваем из сертификата открытый ключ.
            // Он всегда ГОСТовый см. выше.
            AsymmetricAlgorithm asym = certificate.PublicKey.Key;
            // Шифруем симметричный ключ xmlKey (ключ шифрования сообщения) на 
            // открытом ключе получателя :). То есть отрабатывает экспорт по KeyTransport
            // Начальное значение gost28147.Mode и gost28147.Padding не важно 
            // EncryptData их переставляет в соответствии с this.Mode
            // и this.Padding

            if (asym is Gost3410)
            {
                xmlKey.CipherData.CipherValue = EncryptKey(gost28147,
                    asym as Gost3410);
                xmlKey.EncryptionMethod = new EncryptionMethod(XmlEncGostKeyTransportUrl);
            }
            else if (asym is Gost3410_2012_256)
            {
                xmlKey.CipherData.CipherValue = EncryptKey(gost28147,
                    asym as Gost3410_2012_256);
                xmlKey.EncryptionMethod = new EncryptionMethod(XmlEncGost2012_256KeyTransportUrl);
            }
            else if (asym is Gost3410_2012_512)
            {
                xmlKey.CipherData.CipherValue = EncryptKey(gost28147,
                    asym as Gost3410_2012_512);
                xmlKey.EncryptionMethod = new EncryptionMethod(XmlEncGost2012_512KeyTransportUrl);
            }
            else
            {
                throw new NotSupportedException(SR.NotSupported_KeyAlgorithm);
            }

            // Создаем xml node для encrypted key по xmlKey
            // (ключ шифрования сообщения)
            KeyInfoEncryptedKey encryptedKey = new KeyInfoEncryptedKey(xmlKey);
            // Подцепляем в сообщение зашифрованный ключ
            data.KeyInfo.AddClause(encryptedKey);
            // Подцепляем в сообщение зашифрованные данные
            data.CipherData.CipherValue = EncryptData(
                inputElement, gost28147, false);
            return data;
            // end: gost
        }

        // Encrypts the given element with the key name specified. A corresponding key name mapping 
        // has to be defined before calling this method. The key name is added as
        // a KeyNameInfo KeyInfo to an EncryptedKey (AES session key) generated randomly.
        public EncryptedData Encrypt(XmlElement inputElement, string keyName)
        {
            if (inputElement == null)
                throw new ArgumentNullException(nameof(inputElement));
            if (keyName == null)
                throw new ArgumentNullException(nameof(keyName));

            object encryptionKey = null;
            if (_keyNameMapping != null)
                encryptionKey = _keyNameMapping[keyName];

            if (encryptionKey == null)
                throw new CryptographicException(SR.Cryptography_Xml_MissingEncryptionKey);

            // kek is either a SymmetricAlgorithm or an RSA key, otherwise, we wouldn't be able to insert it in the hash table
            SymmetricAlgorithm symKey = encryptionKey as SymmetricAlgorithm;
            RSA rsa = encryptionKey as RSA;

            // Create the EncryptedData object, using an AES-256 session key by default.
            EncryptedData ed = new EncryptedData();
            ed.Type = EncryptedXml.XmlEncElementUrl;
            ed.EncryptionMethod = new EncryptionMethod(EncryptedXml.XmlEncAES256Url);

            // Include the key name in the EncryptedKey KeyInfo.
            string encryptionMethod = null;
            if (symKey == null)
            {
                encryptionMethod = EncryptedXml.XmlEncRSA15Url;
            }
            else if (symKey is TripleDES)
            {
                // CMS Triple DES Key Wrap
                encryptionMethod = EncryptedXml.XmlEncTripleDESKeyWrapUrl;
            }
            else if (symKey is Rijndael || symKey is Aes)
            {
                // FIPS AES Key Wrap
                switch (symKey.KeySize)
                {
                    case 128:
                        encryptionMethod = EncryptedXml.XmlEncAES128KeyWrapUrl;
                        break;
                    case 192:
                        encryptionMethod = EncryptedXml.XmlEncAES192KeyWrapUrl;
                        break;
                    case 256:
                        encryptionMethod = EncryptedXml.XmlEncAES256KeyWrapUrl;
                        break;
                }
            }
            else
            {
                // throw an exception if the transform is not in the previous categories
                throw new CryptographicException(SR.Cryptography_Xml_NotSupportedCryptographicTransform);
            }
            EncryptedKey ek = new EncryptedKey();
            ek.EncryptionMethod = new EncryptionMethod(encryptionMethod);
            ek.KeyInfo.AddClause(new KeyInfoName(keyName));

            // Create a random AES session key and encrypt it with the public key associated with the certificate.
            RijndaelManaged rijn = new RijndaelManaged();
            ek.CipherData.CipherValue = (symKey == null ? EncryptedXml.EncryptKey(rijn.Key, rsa, false) : EncryptedXml.EncryptKey(rijn.Key, symKey));

            // Encrypt the input element with the random session key that we've created above.
            KeyInfoEncryptedKey kek = new KeyInfoEncryptedKey(ek);
            ed.KeyInfo.AddClause(kek);
            ed.CipherData.CipherValue = EncryptData(inputElement, rijn, false);

            return ed;
        }

        // decrypts the document using the defined key mapping in GetDecryptionKey
        // The behaviour of this method can be extended because GetDecryptionKey is virtual
        // the document is decrypted in place
        public void DecryptDocument()
        {
            // Look for all EncryptedData elements and decrypt them
            XmlNamespaceManager nsm = new XmlNamespaceManager(_document.NameTable);
            nsm.AddNamespace("enc", EncryptedXml.XmlEncNamespaceUrl);
            XmlNodeList encryptedDataList = _document.SelectNodes("//enc:EncryptedData", nsm);
            if (encryptedDataList != null)
            {
                foreach (XmlNode encryptedDataNode in encryptedDataList)
                {
                    XmlElement encryptedDataElement = encryptedDataNode as XmlElement;
                    EncryptedData ed = new EncryptedData();
                    ed.LoadXml(encryptedDataElement);
                    SymmetricAlgorithm symAlg = GetDecryptionKey(ed, null);
                    if (symAlg == null)
                        throw new CryptographicException(SR.Cryptography_Xml_MissingDecryptionKey);
                    byte[] decrypted = DecryptData(ed, symAlg);
                    ReplaceData(encryptedDataElement, decrypted);
                }
            }
        }

        // encrypts the supplied arbitrary data
        public byte[] EncryptData(byte[] plaintext, SymmetricAlgorithm symmetricAlgorithm)
        {
            if (plaintext == null)
                throw new ArgumentNullException(nameof(plaintext));
            if (symmetricAlgorithm == null)
                throw new ArgumentNullException(nameof(symmetricAlgorithm));

            // save the original symmetric algorithm
            CipherMode origMode = symmetricAlgorithm.Mode;
            PaddingMode origPadding = symmetricAlgorithm.Padding;

            byte[] cipher = null;
            try
            {
                symmetricAlgorithm.Mode = _mode;
                symmetricAlgorithm.Padding = _padding;

                ICryptoTransform enc = symmetricAlgorithm.CreateEncryptor();
                cipher = enc.TransformFinalBlock(plaintext, 0, plaintext.Length);
            }
            finally
            {
                // now restore the original symmetric algorithm
                symmetricAlgorithm.Mode = origMode;
                symmetricAlgorithm.Padding = origPadding;
            }

            byte[] output = null;
            if (_mode == CipherMode.ECB)
            {
                output = cipher;
            }
            else
            {
                byte[] IV = symmetricAlgorithm.IV;
                output = new byte[cipher.Length + IV.Length];
                Buffer.BlockCopy(IV, 0, output, 0, IV.Length);
                Buffer.BlockCopy(cipher, 0, output, IV.Length, cipher.Length);
            }
            return output;
        }

        // encrypts the supplied input element
        public byte[] EncryptData(XmlElement inputElement, SymmetricAlgorithm symmetricAlgorithm, bool content)
        {
            if (inputElement == null)
                throw new ArgumentNullException(nameof(inputElement));
            if (symmetricAlgorithm == null)
                throw new ArgumentNullException(nameof(symmetricAlgorithm));

            byte[] plainText = (content ? _encoding.GetBytes(inputElement.InnerXml) : _encoding.GetBytes(inputElement.OuterXml));
            return EncryptData(plainText, symmetricAlgorithm);
        }

        // decrypts the supplied EncryptedData
        public byte[] DecryptData(EncryptedData encryptedData, SymmetricAlgorithm symmetricAlgorithm)
        {
            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));
            if (symmetricAlgorithm == null)
                throw new ArgumentNullException(nameof(symmetricAlgorithm));

            // get the cipher value and decrypt
            byte[] cipherValue = GetCipherValue(encryptedData.CipherData);

            // save the original symmetric algorithm
            CipherMode origMode = symmetricAlgorithm.Mode;
            PaddingMode origPadding = symmetricAlgorithm.Padding;
            byte[] origIV = symmetricAlgorithm.IV;

            // read the IV from cipherValue
            byte[] decryptionIV = null;
            if (_mode != CipherMode.ECB)
                decryptionIV = GetDecryptionIV(encryptedData, null);

            byte[] output = null;
            try
            {
                int lengthIV = 0;
                if (decryptionIV != null)
                {
                    symmetricAlgorithm.IV = decryptionIV;
                    lengthIV = decryptionIV.Length;
                }
                symmetricAlgorithm.Mode = _mode;
                symmetricAlgorithm.Padding = _padding;

                ICryptoTransform dec = symmetricAlgorithm.CreateDecryptor();
                output = dec.TransformFinalBlock(cipherValue, lengthIV, cipherValue.Length - lengthIV);
            }
            finally
            {
                // now restore the original symmetric algorithm
                symmetricAlgorithm.Mode = origMode;
                symmetricAlgorithm.Padding = origPadding;
                symmetricAlgorithm.IV = origIV;
            }

            return output;
        }

        // This method replaces an EncryptedData element with the decrypted sequence of bytes
        public void ReplaceData(XmlElement inputElement, byte[] decryptedData)
        {
            if (inputElement == null)
                throw new ArgumentNullException(nameof(inputElement));
            if (decryptedData == null)
                throw new ArgumentNullException(nameof(decryptedData));

            XmlNode parent = inputElement.ParentNode;
            if (parent.NodeType == XmlNodeType.Document)
            {
                // We're replacing the root element, but we can't just wholesale replace the owner
                // document's InnerXml, since we need to preserve any other top-level XML elements (such as
                // comments or the XML entity declaration.  Instead, create a new document with the
                // decrypted XML, import it into the existing document, and replace just the root element.
                XmlDocument importDocument = new XmlDocument();
                importDocument.PreserveWhitespace = true;
                string decryptedString = _encoding.GetString(decryptedData);
                using (StringReader sr = new StringReader(decryptedString))
                {
                    using (XmlReader xr = XmlReader.Create(sr, Utils.GetSecureXmlReaderSettings(_xmlResolver)))
                    {
                        importDocument.Load(xr);
                    }
                }

                XmlNode importedNode = inputElement.OwnerDocument.ImportNode(importDocument.DocumentElement, true);

                parent.RemoveChild(inputElement);
                parent.AppendChild(importedNode);
            }
            else
            {
                XmlNode dummy = parent.OwnerDocument.CreateElement(parent.Prefix, parent.LocalName, parent.NamespaceURI);

                try
                {
                    parent.AppendChild(dummy);

                    // Replace the children of the dummy node with the sequence of bytes passed in.
                    // The string will be parsed into DOM objects in the context of the parent of the EncryptedData element.
                    dummy.InnerXml = _encoding.GetString(decryptedData);

                    // Move the children of the dummy node up to the parent.
                    XmlNode child = dummy.FirstChild;
                    XmlNode sibling = inputElement.NextSibling;

                    XmlNode nextChild = null;
                    while (child != null)
                    {
                        nextChild = child.NextSibling;
                        parent.InsertBefore(child, sibling);
                        child = nextChild;
                    }
                }
                finally
                {
                    // Remove the dummy element.
                    parent.RemoveChild(dummy);
                }

                // Remove the EncryptedData element
                parent.RemoveChild(inputElement);
            }
        }

        //
        // public static methods
        //

        // replaces the inputElement with the provided EncryptedData
        public static void ReplaceElement(XmlElement inputElement, EncryptedData encryptedData, bool content)
        {
            if (inputElement == null)
                throw new ArgumentNullException(nameof(inputElement));
            if (encryptedData == null)
                throw new ArgumentNullException(nameof(encryptedData));

            // First, get the XML representation of the EncryptedData object
            XmlElement elemED = encryptedData.GetXml(inputElement.OwnerDocument);
            switch (content)
            {
                case true:
                    // remove all children of the input element
                    Utils.RemoveAllChildren(inputElement);
                    // then append the encrypted data as a child of the input element
                    inputElement.AppendChild(elemED);
                    break;
                case false:
                    XmlNode parentNode = inputElement.ParentNode;
                    // remove the input element from the containing document
                    parentNode.ReplaceChild(elemED, inputElement);
                    break;
            }
        }

        // wraps the supplied input key data using the provided symmetric algorithm
        public static byte[] EncryptKey(byte[] keyData, SymmetricAlgorithm symmetricAlgorithm)
        {
            if (keyData == null)
                throw new ArgumentNullException(nameof(keyData));
            if (symmetricAlgorithm == null)
                throw new ArgumentNullException(nameof(symmetricAlgorithm));

            if (symmetricAlgorithm is TripleDES)
            {
                // CMS Triple DES Key Wrap
                return SymmetricKeyWrap.TripleDESKeyWrapEncrypt(symmetricAlgorithm.Key, keyData);
            }
            else if (symmetricAlgorithm is Rijndael || symmetricAlgorithm is Aes)
            {
                // FIPS AES Key Wrap
                return SymmetricKeyWrap.AESKeyWrapEncrypt(symmetricAlgorithm.Key, keyData);
            }
            // throw an exception if the transform is not in the previous categories
            throw new CryptographicException(SR.Cryptography_Xml_NotSupportedCryptographicTransform);
        }


        // encrypts the supplied input key data using an RSA key and specifies whether we want to use OAEP 
        // padding or PKCS#1 v1.5 padding as described in the PKCS specification
        public static byte[] EncryptKey(byte[] keyData, RSA rsa, bool useOAEP)
        {
            if (keyData == null)
                throw new ArgumentNullException(nameof(keyData));
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));

            if (useOAEP)
            {
                RSAOAEPKeyExchangeFormatter rsaFormatter = new RSAOAEPKeyExchangeFormatter(rsa);
                return rsaFormatter.CreateKeyExchange(keyData);
            }
            else
            {
                RSAPKCS1KeyExchangeFormatter rsaFormatter = new RSAPKCS1KeyExchangeFormatter(rsa);
                return rsaFormatter.CreateKeyExchange(keyData);
            }
        }

        // decrypts the supplied wrapped key using the provided symmetric algorithm
        public static byte[] DecryptKey(byte[] keyData, SymmetricAlgorithm symmetricAlgorithm)
        {
            if (keyData == null)
                throw new ArgumentNullException(nameof(keyData));
            if (symmetricAlgorithm == null)
                throw new ArgumentNullException(nameof(symmetricAlgorithm));

            if (symmetricAlgorithm is TripleDES)
            {
                // CMS Triple DES Key Wrap
                return SymmetricKeyWrap.TripleDESKeyWrapDecrypt(symmetricAlgorithm.Key, keyData);
            }
            else if (symmetricAlgorithm is Rijndael || symmetricAlgorithm is Aes)
            {
                // FIPS AES Key Wrap
                return SymmetricKeyWrap.AESKeyWrapDecrypt(symmetricAlgorithm.Key, keyData);
            }
            // throw an exception if the transform is not in the previous categories
            throw new CryptographicException(SR.Cryptography_Xml_NotSupportedCryptographicTransform);
        }

        // decrypts the supplied data using an RSA key and specifies whether we want to use OAEP 
        // padding or PKCS#1 v1.5 padding as described in the PKCS specification
        public static byte[] DecryptKey(byte[] keyData, RSA rsa, bool useOAEP)
        {
            if (keyData == null)
                throw new ArgumentNullException(nameof(keyData));
            if (rsa == null)
                throw new ArgumentNullException(nameof(rsa));

            if (useOAEP)
            {
                RSAOAEPKeyExchangeDeformatter rsaDeformatter = new RSAOAEPKeyExchangeDeformatter(rsa);
                return rsaDeformatter.DecryptKeyExchange(keyData);
            }
            else
            {
                RSAPKCS1KeyExchangeDeformatter rsaDeformatter = new RSAPKCS1KeyExchangeDeformatter(rsa);
                return rsaDeformatter.DecryptKeyExchange(keyData);
            }
        }

        // begin: gost
        /// <summary>
        /// Экспорт симметричного ключа
        /// <see cref="Gost28147"/> 
        /// на пользовательском ключе.
        /// </summary>
        /// 
        /// <param name="simm">Симметричный экспортируемый ключ.</param>
        /// <param name="gost">Пользовательский ключ экспорта.</param>
        /// 
        /// <returns>Байтовый массив, содержащий зашифрованный ключ.</returns>
        /// 
        /// <argnull name="simm" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данную операцию иногда называют зашифрованием 
        /// симметричного ключа алгоритма на ассиметричном.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Предоставляем public доступ по аналогии с RSA.</para></intdoc>
        public static byte[] EncryptKey(Gost28147 simm, Gost3410 gost)
        {
            if (simm == null)
            {
                throw new ArgumentNullException("keyData");
            }
            if (gost == null)
            {
                throw new ArgumentNullException("gost");
            }
            GostKeyExchangeFormatter formatter = new GostKeyExchangeFormatter(gost);
            return formatter.CreateKeyExchangeData(simm);
        }

        /// <summary>
        /// Экспорт симметричного ключа
        /// <see cref="Gost28147"/> 
        /// на пользовательском ключе.
        /// </summary>
        /// 
        /// <param name="simm">Симметричный экспортируемый ключ.</param>
        /// <param name="gost">Пользовательский ключ экспорта.</param>
        /// <returns>Байтовый массив, содержащий зашифрованный ключ.</returns>
        /// 
        /// <argnull name="simm" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данную операцию иногда называют зашифрованием 
        /// симметричного ключа алгоритма на ассиметричном.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Предоставляем public доступ по аналогии с RSA.</para></intdoc>
        public static byte[] EncryptKey(Gost28147 simm, Gost3410_2012_256 gost)
        {
            if (simm == null)
            {
                throw new ArgumentNullException("keyData");
            }
            if (gost == null)
            {
                throw new ArgumentNullException("gost");
            }
            GostKeyExchangeFormatter formatter = new GostKeyExchangeFormatter(gost);
            return formatter.CreateKeyExchangeData(simm);
        }

        /// <summary>
        /// Экспорт симметричного ключа
        /// <see cref="Gost28147"/> 
        /// на пользовательском ключе.
        /// </summary>
        /// 
        /// <param name="simm">Симметричный экспортируемый ключ.</param>
        /// <param name="gost">Пользовательский ключ экспорта.</param>
        /// <param name="wrapMethod">Алгоритм экпорта симметричных ключей</param>
        /// <returns>Байтовый массив, содержащий зашифрованный ключ.</returns>
        /// 
        /// <argnull name="simm" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данную операцию иногда называют зашифрованием 
        /// симметричного ключа алгоритма на ассиметричном.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Предоставляем public доступ по аналогии с RSA.</para></intdoc>
        public static byte[] EncryptKey(Gost28147 simm, Gost3410_2012_256 gost, GostKeyWrapMethod wrapMethod)
        {
            if (simm == null)
            {
                throw new ArgumentNullException("keyData");
            }
            if (gost == null)
            {
                throw new ArgumentNullException("gost");
            }
            GostKeyExchangeFormatter formatter = new GostKeyExchangeFormatter(gost);
            return formatter.CreateKeyExchangeData(simm, wrapMethod);
        }

        /// <summary>
        /// Экспорт симметричного ключа
        /// Gost28147
        /// на пользовательском ключе.
        /// </summary>
        /// 
        /// <param name="simm">Симметричный экспортируемый ключ.</param>
        /// <param name="gost">Пользовательский ключ экспорта.</param>
        /// <returns>Байтовый массив, содержащий зашифрованный ключ.</returns>
        /// 
        /// <argnull name="simm" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данную операцию иногда называют зашифрованием 
        /// симметричного ключа алгоритма на ассиметричном.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Предоставляем public доступ по аналогии с RSA.</para></intdoc>
        public static byte[] EncryptKey(Gost28147 simm, Gost3410_2012_512 gost)
        {
            if (simm == null)
            {
                throw new ArgumentNullException("keyData");
            }
            if (gost == null)
            {
                throw new ArgumentNullException("gost");
            }
            GostKeyExchangeFormatter formatter = new GostKeyExchangeFormatter(gost);
            return formatter.CreateKeyExchangeData(simm);
        }

        /// <summary>
        /// Экспорт симметричного ключа
        /// <see cref="Gost28147"/> 
        /// на пользовательском ключе.
        /// </summary>
        /// 
        /// <param name="simm">Симметричный экспортируемый ключ.</param>
        /// <param name="gost">Пользовательский ключ экспорта.</param>
        /// <param name="wrapMethod">Алгоритм экпорта</param>
        /// <returns>Байтовый массив, содержащий зашифрованный ключ.</returns>
        /// 
        /// <argnull name="simm" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данную операцию иногда называют зашифрованием 
        /// симметричного ключа алгоритма на ассиметричном.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Предоставляем public доступ по аналогии с RSA.</para></intdoc>
        public static byte[] EncryptKey(Gost28147 simm, Gost3410_2012_512 gost, GostKeyWrapMethod wrapMethod)
        {
            if (simm == null)
            {
                throw new ArgumentNullException("keyData");
            }
            if (gost == null)
            {
                throw new ArgumentNullException("gost");
            }
            GostKeyExchangeFormatter formatter = new GostKeyExchangeFormatter(gost);
            return formatter.CreateKeyExchangeData(simm, wrapMethod);
        }

        /// <summary>
        /// Экспорт симметричного ключа на симметричном ключе.
        /// </summary>
        /// 
        /// <param name="keyToEncrypt">Ключ, который экспортируется 
        /// (зашифровывается).</param>
        /// <param name="exportingKey">Ключ экспорта (зашифрования)</param>
        /// <param name="method">Метод экспорта (зашифрования).</param>
        /// 
        /// <returns>Экспортированный (зашифрованный ключ).</returns>
        /// 
        /// <argnull name="keyToEncrypt" />
        /// <argnull name="exportingKey" />
        public static byte[] EncryptKey(SymmetricAlgorithm keyToEncrypt,
            Gost28147 exportingKey, GostKeyWrapMethod method)
        {
            // Это дополнительная функция, не DETOUR
            if (keyToEncrypt == null)
            {
                throw new ArgumentNullException("keyToEncrypt");
            }
            if (exportingKey == null)
            {
                throw new ArgumentNullException("exportingKey");
            }
            return exportingKey.Wrap((Gost28147)keyToEncrypt, method);
        }

        /// <summary>
        /// Расшифровывание элемента &#60;EncryptedKey&#62;
        /// с использованием алгоритма асимметричного шифрования
        /// и импорт его в класс симметричного алгоритма.
        /// </summary>
        /// 
        /// <returns><see cref="SymmetricAlgorithm"/>, содержащий импортированный 
        /// ключ.</returns>
        /// 
        /// <param name="keyData">Байтовый массив с зашифрованным элементом 
        /// &#60;EncryptedKey&#62;</param>
        /// <param name="gost">Ассиметричный ключ, используемый для расшифровки 
        /// ключевай информации.</param>
        /// <param name="symmetricAlgorithmUri">URI алгоритм экспорта.</param>
        /// 
        /// <argnull name="keyData" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данный метод производит расшифрование 
        /// средствами импорта криптопровайдера и не требует прав по 
        /// экспорту/импорту в байтовый массив.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Кроме открытия доступа к ГОСТ преобразованию
        /// по аналогии с RSA, предоставляем досуп, для возможности
        /// импорта без операций преобразования в байтовый массив.</para>
        /// </intdoc>
        public static SymmetricAlgorithm DecryptKey(
            byte[] keyData, Gost3410 gost, string symmetricAlgorithmUri)
        {
            // TODO: Use symmetricAlgorithmUri для разных алгоритмов симметричных ключей
            if (keyData == null)
                throw new ArgumentNullException("keyData");
            if (gost == null)
                throw new ArgumentNullException("gost");
            GostKeyExchangeDeformatter deformatter =
                new GostKeyExchangeDeformatter(gost);
            return deformatter.DecryptKeyExchangeData(keyData);
        }

        /// <summary>
        /// Расшифровывание элемента &#60;EncryptedKey&#62;
        /// с использованием алгоритма асимметричного шифрования
        /// и импорт его в класс симметричного алгоритма.
        /// </summary>
        /// 
        /// <returns><see cref="SymmetricAlgorithm"/>, содержащий импортированный 
        /// ключ.</returns>
        /// 
        /// <param name="keyData">Байтовый массив с зашифрованным элементом 
        /// &#60;EncryptedKey&#62;</param>
        /// <param name="gost">Ассиметричный ключ, используемый для расшифровки 
        /// ключевай информации.</param>
        /// <param name="symmetricAlgorithmUri">URI алгоритм экспорта.</param>
        /// <argnull name="keyData" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данный метод производит расшифрование 
        /// средствами импорта криптопровайдера и не требует прав по 
        /// экспорту/импорту в байтовый массив.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Кроме открытия доступа к ГОСТ преобразованию
        /// по аналогии с RSA, предоставляем досуп, для возможности
        /// импорта без операций преобразования в байтовый массив.</para>
        /// </intdoc>
        public static SymmetricAlgorithm DecryptKey(
            byte[] keyData, Gost3410_2012_256 gost, string symmetricAlgorithmUri)
        {
            // TODO: Use symmetricAlgorithmUri для разных алгоритмов симметричных ключей
            if (keyData == null)
                throw new ArgumentNullException("keyData");
            if (gost == null)
                throw new ArgumentNullException("gost");
            GostKeyExchangeDeformatter deformatter =
                new GostKeyExchangeDeformatter(gost);
            return deformatter.DecryptKeyExchangeData(keyData);
        }

        /// <summary>
        /// Расшифровывание элемента &#60;EncryptedKey&#62;
        /// с использованием алгоритма асимметричного шифрования
        /// и импорт его в класс симметричного алгоритма.
        /// </summary>
        /// 
        /// <returns><see cref="SymmetricAlgorithm"/>, содержащий импортированный 
        /// ключ.</returns>
        /// 
        /// <param name="keyData">Байтовый массив с зашифрованным элементом 
        /// &#60;EncryptedKey&#62;</param>
        /// <param name="gost">Ассиметричный ключ, используемый для расшифровки 
        /// ключевай информации.</param>
        /// <param name="symmetricAlgorithmUri">URI алгоритм экспорта.</param>
        /// <argnull name="keyData" />
        /// <argnull name="gost" />
        /// 
        /// <remarks><para>Данный метод производит расшифрование 
        /// средствами импорта криптопровайдера и не требует прав по 
        /// экспорту/импорту в байтовый массив.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        /// 
        /// <intdoc><para>Кроме открытия доступа к ГОСТ преобразованию
        /// по аналогии с RSA, предоставляем досуп, для возможности
        /// импорта без операций преобразования в байтовый массив.</para>
        /// </intdoc>
        public static SymmetricAlgorithm DecryptKey(
            byte[] keyData, Gost3410_2012_512 gost, string symmetricAlgorithmUri)
        {
            // TODO: Use symmetricAlgorithmUri для разных алгоритмов симметричных ключей
            if (keyData == null)
                throw new ArgumentNullException("keyData");
            if (gost == null)
                throw new ArgumentNullException("gost");
            GostKeyExchangeDeformatter deformatter =
                new GostKeyExchangeDeformatter(gost);
            return deformatter.DecryptKeyExchangeData(keyData);
        }

        /// <summary>
        /// Расшифровывание элемента &#60;EncryptedKey&#62;
        /// с использованием алгоритма асимметричного шифрования
        /// и импорт его в класс симметричного алгоритма.
        /// </summary>
        /// 
        /// <param name="keyData">Массив байтов, представляющий зашифрованный 
        /// элемент &lt;EncryptedKey&gt;.</param>
        /// <param name="rsa">Асимметричный ключ, который используется для 
        /// расшифрования <paramref name="keyData"/></param>
        /// <param name="useOAEP">Значение, которое указывает, используется ли 
        /// заполнение Optimal Asymmetric Encryption Padding (OAEP).</param>
        /// <param name="symmetricAlgorithmUri">URI алгоритма создаваемого 
        /// ключа.</param>
        /// 
        /// <returns>Ключ в виде класса симметричного алгоритма.</returns>
        /// 
        /// <remarks><para>Функция выполняет пробразование в массив байтов,
        /// а затем импорт в класс; поэтому не применима для алгоритмов
        /// не допускающих импорт симметричных ключей в чистом виде.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        public static SymmetricAlgorithm DecryptKey(byte[] keyData,
            RSA rsa, bool useOAEP, string symmetricAlgorithmUri)
        {
            // Proxy на соответствующую функцию, но возвращающую SymmetricAlgorithm
            byte[] buffer1 = EncryptedXml.DecryptKey(keyData, rsa, useOAEP);
            if (buffer1 == null)
            {
                throw new CryptographicException(SR.Cryptography_Xml_MissingDecryptionKey);
            }
            SymmetricAlgorithm algorithm1 =
                (SymmetricAlgorithm)CryptoConfig.CreateFromName(symmetricAlgorithmUri);
            algorithm1.Key = buffer1;
            return algorithm1;
        }

        /// <summary>
        /// Расшифровывание элемент &#60;EncryptedKey&#62;
        /// с использованием алгоритма симметричного шифрования
        /// и импорт его в класс симметричного алгоритма.
        /// </summary>
        /// 
        /// <param name="keyData">Зашифрованный ключ.</param>
        /// <param name="symmetricAlgorithm">Ключ расшифрования.</param>
        /// <param name="symmetricAlgorithmUri">URI алгоритма 
        /// получаемого ключа.</param>
        /// <param name="encryptionKeyAlgorithm">URI алгоритма 
        /// расшифрования ключа.</param>
        /// 
        /// <returns>Ключ в виде класса симметричного алгоритма.</returns>
        /// 
        /// <remarks><para>Функция выполняет пробразование в массив байтов,
        /// а затем импорт в класс; поэтому не применима для алгоритмов
        /// не допускающих импорт симметричных ключей в чистом виде.</para>
        /// <para>Классы шифрования XML платформы .NET Framework реализуют спецификации 
        /// шифрования XML, определенные консорциумом W3C:
        /// <a href="http://www.w3.org/TR/xmlenc-core">XML Encryption Syntax and Processing</a>.
        /// Дополненения к спецификации для российских стандартов
        /// описано в <a href="http://GOSTXMLMORE">Using GOST Algorithms for XML Security</a>.
        /// </para></remarks>
        public static SymmetricAlgorithm DecryptKey(byte[] keyData,
            SymmetricAlgorithm symmetricAlgorithm, string symmetricAlgorithmUri,
            string encryptionKeyAlgorithm)
        {
            Gost28147 gost = symmetricAlgorithm as Gost28147;
            if (gost != null)
            {
                if (encryptionKeyAlgorithm.Equals(XmlEncGostCryptoProKeyWrapUrl))
                {
                    return gost.Unwrap(keyData, GostKeyWrapMethod.CryptoProKeyWrap);
                }
                if (encryptionKeyAlgorithm.Equals(XmlEncGostCryptoPro12KeyWrapUrl))
                {
                    return gost.Unwrap(keyData, GostKeyWrapMethod.CryptoPro12KeyWrap);
                }
                if (encryptionKeyAlgorithm.Equals(XmlEncGost28147KeyWrapUrl))
                {
                    return gost.Unwrap(keyData, GostKeyWrapMethod.GostKeyWrap);
                }
                throw new CryptographicException(SR.Cryptography_Xml_MissingAlgorithm);
            }
            // Proxy на соответствующую функцию, но возвращающую SymmetricAlgorithm
            byte[] buffer1 = EncryptedXml.DecryptKey(keyData, symmetricAlgorithm);
            if (buffer1 == null)
                throw new CryptographicException(SR.Cryptography_Xml_MissingDecryptionKey);
            SymmetricAlgorithm algorithm1 = (SymmetricAlgorithm)
                CryptoConfig.CreateFromName(symmetricAlgorithmUri);
            algorithm1.Key = buffer1;
            return algorithm1;
        }
        // end: gost
    }
}
