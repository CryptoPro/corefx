// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Diagnostics;
using System.IO;
using Internal.NativeCrypto;
using static Internal.NativeCrypto.CapiHelper;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Реализация алгоритма подписи по ГОСТ Р 34.10 через 
    /// Cryptographic Service Provider (CSP). 
    /// Этот класс не наследуется.
    /// </summary>
    /// 
    /// <remarks><para> Класс <c>Gost3410CryptoServiceProvider</c> 
    /// используется для создания цифровой подписи, формирования общего 
    /// секрета  (Shared Secret). Алгоритм использует секретный ключ длиной 
    /// 256, и открытый ключ длиной 512 бит.</para>
    /// </remarks>
    /// 
    /// <basedon cref="System.Security.Cryptography.RSACryptoServiceProvider"/>
    /// <basedon cref="System.Security.Cryptography.DSACryptoServiceProvider"/>
    /// 
    /// <doc-sample path="Simple\Sign" name="Gost3410CSPSample">Пример работы с 
    /// Gost3410CryptoServiceProvider.
    ///  </doc-sample>
    ///  
    /// <intdoc><para>При реализации убрана длина ключа, она всегда const</para>
    /// </intdoc>
    /// 
    /// <cspversions />
    public sealed class Gost3410CryptoServiceProvider : Gost3410, ICspAsymmetricAlgorithm
    {
        /// <summary>
        /// Признак наличия только открытого ключа, без секретного.
        /// </summary>
        /// <intdoc><para>
        /// Не существует способа определить, какому ключу 
        /// соответствует HANDLE: секретному или открытому. Мы держим 
        /// эту информацию прямо внутри класса, MS скорее всего
        /// держит ее внутри HANDLE (НЕ CSP HANDLE).</para>
        /// <para>Считаем, что единственно возможный способ
        /// получить открытый ключ, это импорт BLOB, 
        /// во всех остальных случаях он стоит в <see langword="false"/>.</para>
        /// </intdoc>
        private bool _publicOnly;

        /// <summary>
        /// Флаг LOCALMACHINE для использования 
        /// </summary>
        private static volatile CspProviderFlags s_useMachineKeyStore = 0;

        /// <summary>
        /// Тип ключа
        /// </summary>
        private int _keySpec;

        /// <summary>
        /// Признак наличия ключа в CSP.
        /// </summary>
        /// <intdoc>
        /// <para>Поведение очень запутанное, поэтому описываю все что 
        /// удалось выяснить.</para>
        /// <para>1. Установка PersistKeyInCsp в <see langword="false"/> 
        /// не удаляет контейнер немедленно.</para>
        /// <para>2. Получение флага PersistKeyInCsp не обращается на прямую к 
        /// контейнеру.</para>
        /// <para>3. После генерации ключа в случайном контейнере, 
        /// PersistKeyInCsp <see langword="true"/>, но контейнер будет удален 
        /// после закрытия.
        /// </para>
        /// <para>4. До генерации ключа в в случайном контейнере, </para>
        /// установка PersistKeyInCsp <see langword="true"/>, контейнер НЕ 
        /// будет удален после закрытия.
        /// </intdoc>
        private bool _peristKeyInCsp;

        private CspParameters _parameters;

        private bool _randomKeyContainer;

        private SafeKeyHandle _safeKeyHandle;

        private SafeProvHandle _safeProvHandle;

        private Gost3411 _hashImpl;

        /// <summary>
        /// Параметры шифрования
        /// </summary>
        public string CipherOid
        {
            // Если ключ не был создан к моменту обращения - создаётся при обращении к SafeKeyHandle
            get
            {
                return CapiHelper.GetKeyParameterString(SafeKeyHandle, Constants.CLR_CIPHEROID);
            }
            set
            {
                CapiHelper.SetKeyParamString(SafeKeyHandle, GostConstants.KP_CIPHEROID, value);
            }
        }

        /// <summary>
        /// Срок действия закртытого ключа, указанного в KP_NOTAFTER
        /// </summary>
        public DateTimeOffset NotAfter
        {
            get
            {
                byte[] fileTime = CapiHelper.GetKeyParameter(SafeKeyHandle, Constants.CLR_NOTAFTER);
                return DateTimeOffset.FromFileTime(BitConverter.ToInt64(fileTime));
            }
        }

        /// <summary>
        /// Конструктор, создающий объект класса 
        /// <see cref="Gost3410CryptoServiceProvider"/>.
        /// </summary>
        /// 
        /// <remarks><para>Создается контейнер с типом 75 на провайдере
        /// по умолчанию, со случайным именем контейнера. Ключи 
        /// будут храниться в store пользователя или машины в 
        /// зависимости от установленного свойства 
        /// <see cref="Gost3410CryptoServiceProvider.UseMachineKeyStore"/>
        /// в момент создания объекта.</para>
        /// <para>Создание ключей будет отложено до момента, когда
        /// этот ключ реально потребуется.</para>
        /// </remarks>
        /// 
        /// <doc-sample path="Simple\Sign" name="Gost3410CSPSample">Пример создания 
        /// и работы с Gost3410CryptoServiceProvider.
        ///  </doc-sample>
        [SecuritySafeCritical]
        public Gost3410CryptoServiceProvider()
            : this(
                new CspParameters(
                    GostConstants.PROV_GOST_2001_DH,
                    null,
                    null,
                    Gost3410CryptoServiceProvider.s_useMachineKeyStore))
        {
        }

        /// <summary>
        /// Конструктор алгоритма подписи по ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="parameters">Параметры алгоритма.</param>
        /// 
        /// <remarks><para>При создании контейнера без заданного имени
        /// контейнера и без указания флага использования контейнера по 
        /// умолчанию будет создано случайное имя, а создание ключей
        /// будет отложено, до его первого обращения.
        /// </para>
        /// 
        /// <para>При инициализации объекта через данный конструктор 
        /// будут использованы именно эти параметры, в независимости от
        /// флага <see cref="UseMachineKeyStore"/>. По умолчанию значение
        /// флага из 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// устанавливется в использование ключей из хранилищи пользователя.
        /// Для использования ключей из хранилища компьютера 
        /// необходимо установить флаг <see cref="CspParameters.Flags"/>:
        /// <see cref="CspProviderFlags.UseMachineKeyStore"/>.
        /// </para>
        /// </remarks>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        [SecuritySafeCritical]
        public Gost3410CryptoServiceProvider(CspParameters parameters)
        {
            _parameters = CapiHelper.SaveCspParameters(
                CapiHelper.CspAlgorithmType.Gost2001,
                parameters,
                s_useMachineKeyStore,
                out _randomKeyContainer);
            _keySpec = _parameters.KeyNumber;
            LegalKeySizesValue = new KeySizes[] { new KeySizes(GostConstants.GOST_3410EL_SIZE, GostConstants.GOST_3410EL_SIZE, 0) };

            _hashImpl = Gost3411.Create();
            if (!_randomKeyContainer) GetKeyPair();
        }

        [SecuritySafeCritical]
        public Gost3410CryptoServiceProvider(IntPtr hProvHandle, int keySpec)
        {
            _safeProvHandle = new SafeProvHandle(hProvHandle, true);
            _keySpec = keySpec;

            LegalKeySizesValue = new KeySizes[] { new KeySizes(
                GostConstants.GOST_3410EL_SIZE, GostConstants.GOST_3410EL_SIZE,  0) };
            _safeKeyHandle = CapiHelper.GetKeyPairHelper(
                            CspAlgorithmType.Gost2001,
                            keySpec,
                            GostConstants.GOST_3410EL_SIZE,
                            _safeProvHandle);
            _hashImpl = Gost3411.Create();
        }

        protected override byte[] HashData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            // we're sealed and the base should have checked this already
            Debug.Assert(data != null);
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));

            using (HashAlgorithm hash = Gost3411.Create())
            {
                return hash.ComputeHash(data);
            }
        }

        protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            // we're sealed and the base should have checked this already
            Debug.Assert(data != null);
            Debug.Assert(count >= 0 && count <= data.Length);
            Debug.Assert(offset >= 0 && offset <= data.Length - count);
            Debug.Assert(!string.IsNullOrEmpty(hashAlgorithm.Name));

            using (HashAlgorithm hash = Gost3411.Create())
            {
                return hash.ComputeHash(data, offset, count);
            }
        }

        public override byte[] SignData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        {
            byte[] hashVal = _hashImpl.ComputeHash(data, offset, count);
            return SignHash(hashVal, hashAlgorithm);
        }

        public override byte[] SignData(Stream data, HashAlgorithmName hashAlgorithm)
        {
            byte[] hashVal = _hashImpl.ComputeHash(data);
            return SignHash(hashVal, hashAlgorithm);
        }

        ///// <summary>
        ///// Computes the hash value of the specified input stream and signs the resulting hash value.
        ///// </summary>
        ///// <param name="inputStream">The input data for which to compute the hash.</param>
        ///// <returns>The DSA signature for the specified data.</returns>
        //public byte[] SignData(Stream inputStream)
        //{
        //    byte[] hashVal = _gost3411.ComputeHash(inputStream);
        //    return SignHash(hashVal);
        //}

        ///// <summary>
        ///// Computes the hash value of the specified input stream and signs the resulting hash value.
        ///// </summary>
        ///// <param name="buffer">The input data for which to compute the hash.</param>
        ///// <returns>The DSA signature for the specified data.</returns>
        //public byte[] SignData(byte[] buffer)
        //{
        //    byte[] hashVal = _gost3411.ComputeHash(buffer);
        //    return SignHash(hashVal);
        //}

        ///// <summary>
        ///// Signs a byte array from the specified start point to the specified end point.
        ///// </summary>
        ///// <param name="buffer">The input data to sign.</param>
        ///// <param name="offset">The offset into the array from which to begin using data.</param>
        ///// <param name="count">The number of bytes in the array to use as data.</param>
        ///// <returns>The DSA signature for the specified data.</returns>
        //public byte[] SignData(byte[] buffer, int offset, int count)
        //{
        //    byte[] hashVal = _gost3411.ComputeHash(buffer, offset, count);
        //    return SignHash(hashVal);
        //}

        /// <summary>
        /// Вычисляет подпись для заданного значения хэш.
        /// </summary>
        /// 
        /// <param name="rgbHash">Подписываемое значение хэш.</param>
        /// <param name="hashAlgName">Алгоритм ГОСТ 34.11-94</param>
        /// <returns>Подпись хэша, выполненная по алгоритму 
        /// ГОСТ Р 34.10.</returns>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignHash">Пример подписи и 
        ///  проверки подписи хэш.</doc-sample>
        ///  
        /// <intdoc><para>Стандарт допускает только алгоритм хеширования 
        /// ГОСТ Р 34.11. Не таскаем лишний параметр алгоритм хеширования.
        /// </para></intdoc>
        /// 
        /// <remarks><para>Функция тождественна 
        /// CreateSignature.</para></remarks>
        /// 
        /// <argnull name="hash" />
        /// <exception cref="CryptographicException">Объект не содержит 
        /// секретного ключа или хеш имееет неправильный размер.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Sign">Для подписи на не случайном контейнере.
        /// </containerperm>
        public override byte[] SignHash(byte[] rgbHash, HashAlgorithmName hashAlgName)
        {
            if (hashAlgName != HashAlgorithmName.Gost3411)
            {
                throw new CryptographicException(string.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgName.Name));
            }
            return SignHash(rgbHash);
        }

        public override byte[] SignHash(byte[] rgbHash)
        {
            if (rgbHash == null) throw new ArgumentNullException(nameof(rgbHash));
            if (PublicOnly) throw new CryptographicException(SR.Cryptography_CSP_NoPrivateKey);

            if (rgbHash.Length != (GostConstants.GOST3411_SIZE / 8))
            {
                throw new CryptographicException(
                    string.Format(
                        SR.Cryptography_InvalidHashSize,
                        "GOST3411", GostConstants.GOST3411_SIZE / 8));
            }
            GetKeyPair();
            return CapiHelper.SignValue(
                SafeProvHandle,
                SafeKeyHandle,
                _keySpec, //2
                CapiHelper.CALG_RSA_SIGN, //переворачиваем подпись, раньше (Sharpei) переворачивали только в форматтерах
                GostConstants.CALG_GR3411,
                rgbHash);
        }

        /// <summary>
        /// Проверяет подлинность подписи для указанного значения хэш.
        /// </summary>
        /// 
        /// <param name="hash">Хэш, для которого проверяется 
        /// подпись.</param>
        /// <param name="signature">Подпись, подлинность которой 
        /// необходимо проверить.</param>
        /// <param name="hashAlgName">Алгоритм ГОСТ 34.11-94</param>
        /// <returns><see langword="true"/>, если подпись подлинна, 
        /// <see langword="false"/> - иначе.</returns>
        /// 
        /// <remarks>Алгоритм вычисления хэш для ГОСТ Р 34.10 
        /// всегда ГОСТ Р 34.11.</remarks>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignHash">Пример подписи и 
        ///  проверки подписи хэш.</doc-sample>
        ///  
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public override bool VerifyHash(byte[] hash, byte[] signature, HashAlgorithmName hashAlgName)
        {
            if (hashAlgName != HashAlgorithmName.Gost3411)
            {
                throw new CryptographicException(string.Format(SR.Cryptography_UnknownHashAlgorithm, hashAlgName.Name));
            }
            bool ret = VerifyHash(hash, signature);
            return ret;
        }

        /// <summary>
        /// Проверяет подлинность подписи для указанного значения хэш.
        /// </summary>
        /// 
        /// <param name="rgbHash">Хэш, для которого проверяется 
        /// подпись.</param>
        /// <param name="rgbSignature">Подпись, подлинность которой 
        /// необходимо проверить.</param>
        /// 
        /// <returns><see langword="true"/>, если продпись подлинна, 
        /// <see langword="false"/> - иначе.</returns>
        /// 
        /// <remarks>Алгоритм вычисления хэш для ГОСТ Р 34.10 
        /// всегда ГОСТ Р 34.11.</remarks>
        /// 
        /// <doc-sample path="Simple\Sign" name="SignHash">Пример подписи и 
        ///  проверки подписи хэш.</doc-sample>
        ///  
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public bool VerifyHash(byte[] rgbHash, byte[] rgbSignature)
        {
            if (rgbHash == null) throw new ArgumentNullException(nameof(rgbHash));
            if (rgbSignature == null) throw new ArgumentNullException(nameof(rgbSignature));
            if (rgbHash.Length != (GostConstants.GOST3411_SIZE / 8))
            {
                throw new CryptographicException(
                    string.Format(
                        SR.Cryptography_InvalidHashSize,
                        "GOST3411", GostConstants.GOST3411_SIZE / 8));
            }

            GetKeyPair();
            bool ret = CapiHelper.VerifySign(
                _safeProvHandle,
                _safeKeyHandle,
                CapiHelper.CALG_RSA_SIGN, //переворачиваем подпись, раньше (Sharpei) переворачивали только в форматтерах
                GostConstants.CALG_GR3411,
                rgbHash,
                rgbSignature);
            return ret;
        }

        /// <summary>
        /// Экспортирует параметры алгоритма в BLOB.
        /// </summary>
        /// 
        /// <param name="includePrivateParameters">Для экспорта секретного
        /// ключа.</param>
        /// 
        /// <returns>BLOB со структурой описанной для CSP.</returns>
        /// 
        /// <remarks><para>Экспорт секретного ключа не поддерживается.
        /// </para></remarks>
        /// 
        /// <exception cref="CryptographicException">При экспорте секретного
        /// ключа.</exception>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        /// 
        /// <intdoc>Экспорт секретного ключа запрещен, поэтому
        /// не требуются права на экспорт. При экспорте открытого
        /// ключа может потребоваться открытие (создание) контейнера,
        /// поэтому требование прав на открытие.</intdoc>
        public byte[] ExportCspBlob(bool includePrivateParameters)
        {
            // Права на экспорт / импорт проверять бесполезно
            // CSP все равно не поддерживает. Бесполезно да же эмулировать:
            // сделать с этим BLOB потом ничего нельзя.
            if (includePrivateParameters)
                throw new CryptographicException(SR.Argument_InvalidValue, "includePrivateParameters equal true ");
            return CapiHelper.ExportKeyBlob(includePrivateParameters, SafeKeyHandle);
        }

        public override bool VerifyData(
            byte[] data,
            int offset,
            int count,
            byte[] rgbSignature,
            HashAlgorithmName hashAlgorithm)
        {
            byte[] hashVal = _hashImpl.ComputeHash(data, offset, count);
            return VerifyHash(hashVal, rgbSignature);
        }

        /// <summary>
        /// Импорт параметров алгоритма ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="rawData">Байтовый массив, содержащий ключ и параметры
        /// алгоритма ГОСТ Р 34.10.</param>.
        /// 
        /// <remarks><para>Импорт секретного ключа не поддерживается.
        /// </para></remarks>
        /// 
        /// <exception cref="CryptographicException">При экспорте секретного
        /// ключа.</exception>
        public void ImportCspBlob(byte[] rawData)
        {
            SafeKeyHandle safeKeyHandle;

            //Права на экспорт / импорт проверять бесполезно
            // CSP все равно не поддерживает.Бесполезно да же эмулировать:
            // сделать с этим BLOB потом ничего нельзя.

            // Это открытый ключ, поэтому можно его export
            // в verify context.
            // Нет обращения к секретному ключу, поэтому
            // не создаем контейнер без надобности.
            if (IsPublic(rawData))
            {
                SafeProvHandle safeProvHandleTemp = AcquireSafeProviderHandle();

                CapiHelper.ImportKeyBlob(
                    safeProvHandleTemp,
                    CspProviderFlags.NoFlags,
                    false, 
                    rawData,
                    out safeKeyHandle);

                // The property set will take care of releasing any already-existing resources.
                _safeProvHandle = safeProvHandleTemp;
            }
            else
            {
                throw new CryptographicException(SR.CspParameter_invalid, "Cryptography_UserExportBulkBlob");
            }

            // The property set will take care of releasing any already-existing resources.
            _safeKeyHandle = safeKeyHandle;

            if (_parameters != null)
            {
                _parameters.KeyNumber = _safeKeyHandle.KeySpec;
            }

            // Эмулируем MS HANDLE
            _publicOnly = true;
            //throw new PlatformNotSupportedException(SR.Format(SR.Cryptography_CAPI_Required, nameof(CspKeyContainerInfo)));
        }

        /// <summary>
        /// Импорт параметров алгоритма ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="keyBlob">Байтовый массив, содержащий ключ
        /// алгоритма ГОСТ Р 34.10 без параметров. </param>.
        /// 
        /// <param name="paramBlob">Байтовый массив, параметры ключа
        /// алгоритма ГОСТ Р 34.10 без параметров. </param>.
        /// 
        /// <remarks><para>Импорт секретного ключа не поддерживается.
        /// </para></remarks>
        /// 
        /// <exception cref="CryptographicException">При экспорте секретного
        /// ключа.</exception>
        public void ImportCspBlob(byte[] keyBlob, byte[] paramBlob)
        {
            SafeKeyHandle safeKeyHandle;
            var rawData = AsnHelper.EncodePublicBlob(keyBlob, paramBlob, CspAlgorithmType.Gost2001);

            // Права на экспорт / импорт проверять бесполезно
            // CSP все равно не поддерживает. Бесполезно да же эмулировать:
            // сделать с этим BLOB потом ничего нельзя.

            // Это открытый ключ, поэтому можно его export
            // в verify context.
            // Нет обращения к секретному ключу, поэтому
            // не создаем контейнер без надобности.
            if (IsPublic(rawData))
            {
                SafeProvHandle safeProvHandleTemp = AcquireSafeProviderHandle();

                CapiHelper.ImportKeyBlob(
                    safeProvHandleTemp,
                    CspProviderFlags.NoFlags,
                    false,
                   rawData,
                   out safeKeyHandle);

                //The property set will take care of releasing any already-existing resources.
               _safeProvHandle = safeProvHandleTemp;
            }
            else
            {
                throw new CryptographicException(SR.CspParameter_invalid, "Cryptography_UserExportBulkBlob");
            }

            // The property set will take care of releasing any already-existing resources.
            _safeKeyHandle = safeKeyHandle;

            if (_parameters != null)
            {
                _parameters.KeyNumber = SafeKeyHandle.KeySpec;
            }

            // Эмулируем MS HANDLE
            SafeKeyHandle.PublicOnly = true;
            //throw new PlatformNotSupportedException(
            //    SR.Format(SR.Cryptography_CAPI_Required, nameof(CspKeyContainerInfo)));
        }

        /// <summary>
        /// Импорт открытого ключа из структуры CERT_PUBLIC_KEY_INFO
        /// </summary>
        /// <param name="publicKeyInfo"></param>
        public void ImportCertificatePublicKey(byte[] publicKeyInfo)
        {
            SafeKeyHandle safeKeyHandle;
            SafeProvHandle safeProvHandleTemp = AcquireSafeProviderHandle();

            CapiHelper.CryptImportPublicKeyInfo(
                safeProvHandleTemp,
                Interop.Advapi32.CertEncodingType.X509_ASN_ENCODING,
                publicKeyInfo,
                out safeKeyHandle);

            // The property set will take care of releasing any already-existing resources.
            _safeProvHandle = safeProvHandleTemp;

            // The property set will take care of releasing any already-existing resources.
            _safeKeyHandle = safeKeyHandle;

            if (_parameters != null)
            {
                _parameters.KeyNumber = _safeKeyHandle.KeySpec;
            }

            // Эмулируем MS HANDLE
            _publicOnly = true;
        }

        /// <summary>
        /// Экспорт параметров <see cref="Gost3410Parameters"/> 
        /// алгоритма ГОСТ Р 34.10 в CSP.
        /// </summary>
        /// 
        /// <param name="includePrivateParameters"><see langword="true"/>, 
        /// чтобы включить секретный ключ, <see langword="false"/> - для 
        /// экспорта только открытого ключа и его параметров.</param>
        /// 
        /// <returns>Параметры в виде структуры 
        /// <see cref="Gost3410Parameters"/></returns>
        /// 
        /// <remarks>
        /// <if notdefined="userexp"><para>По соображениям безопасности 
        /// в данной сборке при экспорте 
        /// секретного ключа всегда возбуждает исключение 
        /// <see cref="CryptographicException"/>.</para></if>
        /// </remarks>
        /// 
        /// <doc-sample path="Simple\DocBlock" name="ExportParameters" 
        /// region="ExportParameters" />
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        /// <containerperm flag="Export">Для экспорта секретного ключа.
        /// </containerperm>
        public override Gost3410Parameters ExportParameters(bool includePrivateParameters)
        {
            GetKeyPair();
            Gost3410CspObject obj1 = new Gost3410CspObject();
            if (includePrivateParameters)
            {
                throw new CryptographicException(SR.Argument_InvalidValue, "includePrivateParameters equal true ");
            }

            byte[] data = ExportCspBlob(false);
            AsnHelper.DecodePublicBlob(obj1, data, CspAlgorithmType.Gost2001);

            return obj1.Parameters;

            //byte[] cspBlob = ExportCspBlob(includePrivateParameters);
            //return cspBlob.ToGost3410Parameters(includePrivateParameters);
        }

        /// <summary>
        /// Импорт параметров <see cref="Gost3410Parameters"/> 
        /// алгоритма ГОСТ Р 34.10.
        /// </summary>
        /// 
        /// <param name="parameters">Параметры алгоритма 
        /// ГОСТ Р 10.34.</param>
        /// 
        /// <doc-sample path="Simple\DocBlock" name="ImportParameters" 
        /// region="ImportParameters" />
        /// 
        /// <exception cref="CryptographicException">При импорте секретного
        /// ключа.</exception>
        /// 
        /// <remarks>
        /// <if notdefined="userimp"><para>В данной сборке при импорте 
        /// секретного ключа всегда возбуждает исключение 
        /// <see cref="CryptographicException"/>.</para></if>
        /// </remarks>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случайным именем).</containerperm>
        /// <containerperm flag="Import">Для импорта секретного ключа.
        /// </containerperm>
        public override void ImportParameters(Gost3410Parameters parameters)
        {
            Gost3410CspObject pubKey = new Gost3410CspObject(parameters);
            if ((_safeKeyHandle != null) && !_safeKeyHandle.IsClosed)
            {
                _safeKeyHandle.Dispose();
            }

            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            if (Gost3410CryptoServiceProvider.IsPublic(parameters))
            {
                SafeKeyHandle safeKeyHandle;
                // Это открытый ключ, поэтому можно его export
                // в verify context.
                // Нет обращения к секретному ключу, поэтому
                // не создаем контейнер без надобности.
                var safeProvHandleTemp = AcquireSafeProviderHandle();
                if (pubKey == null) throw new ArgumentNullException(nameof(pubKey));

                byte[] keyBlob = AsnHelper.EncodePublicBlob(pubKey, CspAlgorithmType.Gost2001);
                CapiHelper.ImportKeyBlob(
                    safeProvHandleTemp,
                    CspProviderFlags.NoFlags,
                    false,
                    keyBlob,
                    out safeKeyHandle);

                _safeKeyHandle = safeKeyHandle;
                _publicOnly = true;
                return;
            }

            throw new CryptographicException(SR.CspParameter_invalid, "Cryptography_UserExportBulkBlob");
            //throw new PlatformNotSupportedException(SR.Format(SR.Cryptography_CAPI_Required, nameof(CspKeyContainerInfo)));

        }

        /// <summary>
        /// Освобождает неуправляемые объектом класса 
        /// <see cref="Gost3410CryptoServiceProvider"/> ресурсы и, по выбору, 
        /// управляемые. 
        /// </summary>
        /// <param name="disposing"><see langword="true"/>, чтобы освободить 
        /// и управляемые, и неупавляемые ресурсы; <see langword="false"/>, 
        /// чтобы освободить только неуправляемые.</param>
        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (_safeKeyHandle != null && !_safeKeyHandle.IsClosed)
            {
                _safeKeyHandle.Dispose();
            }
            if (_safeProvHandle != null && !_safeProvHandle.IsClosed)
            {
                _safeProvHandle.Dispose();
            }
        }

        /// <summary>
        /// Получает информацию о CSP <see cref="CspKeyContainerInfo"/>, 
        /// в котором хранится ключевая пара.
        /// </summary>
        /// 
        /// <doc-sample path="Simple\KeyManage" name="PersistKeyInCspSample">Пример вызова свойства
        /// CspKeyContainerInfo.</doc-sample>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public CspKeyContainerInfo CspKeyContainerInfo
        {
            [SecuritySafeCritical]
            get
            {
                if (_parameters == null)
                {
                    return null;
                }
                GetKeyPair();
                return new CspKeyContainerInfo(_parameters, _randomKeyContainer);
            }
        }

        /// <summary>
        /// Возвращает длину ключа, используемого в алгоритме, в битах.
        /// </summary>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public override int KeySize
        {
            [SecuritySafeCritical]
            get
            {
                // Проверяем наличие ключа.
                GetKeyPair();
                // В подлиннике обращение к CSP, нам не требуется
                return GostConstants.GOST_3410EL_SIZE;
            }
        }

        /// <summary>
        /// Возвращает или устанавливает флаг, указывающий, должен ли ключ 
        /// храниться в CSP.
        /// </summary>
        /// 
        /// <value>
        /// <see langword="true"/>, если ключ должен храниться в CSP, 
        /// <see langword="false"/> - иначе.
        /// </value>
        /// 
        /// <remarks><para>
        /// Используйте это свойство, если хотите хранить ключ в контейнере
        /// или хотите удалить существующий ключ.</para>
        /// <para>При заданном имени контейнера в <see cref="CspParameters"/>
        /// cвойство <c>PersistKeyInCsp</c> устанавливается в <see langword="true"/>
        /// автоматически и имя испольузуется при инициализации 
        /// <see cref="Gost3410CryptoServiceProvider"/>.
        /// Задать имя CSP можно используя свойство 
        /// <see cref="System.Security.Cryptography.CspKeyContainerInfo.KeyContainerName"/></para>
        /// <para>Если свойство <c>PersistKeyInCsp</c> установлено в 
        /// <see langword="true"/> без инициализации 
        /// <see cref="Gost3410CryptoServiceProvider"/> экземпляром класса
        /// <see cref="CspParameters"/> будет создано случайный
        /// контейнера, с приставкой "CLR" в имени.</para>
        /// </remarks>
        /// 
        /// <doc-sample path="Simple\KeyManage" name="PersistKeyInCspSample">Пример работы
        /// с контейнером закрытого ключа.</doc-sample>
        /// 
        /// <containerperm flag="Open">Для открытия существующего контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера.</containerperm>
        /// <containerperm flag="Delete">Для удаления контейнера.</containerperm>
        /// 
        /// <cspversions><exclude version="30"/><exclude version="20"/><since version="36" build="5276" /></cspversions>
        public bool PersistKeyInCsp
        {
            get
            {
                if (_safeProvHandle == null)
                {
                    lock (this)
                    {
                        if (_safeProvHandle == null)
                            _safeProvHandle = CapiHelper.CreateProvHandle(
                                _parameters, _randomKeyContainer);
                    }
                }
                // return CapiHelper.GetPersistKeyInCsp(SafeProvHandle);
                return _peristKeyInCsp;
            }
            set
            {
                bool oldPersistKeyInCsp = _peristKeyInCsp;
                if (value == oldPersistKeyInCsp)
                {
                    return; // Do nothing
                }
                _peristKeyInCsp = value;
                CapiHelper.SetPersistKeyInCsp(_safeProvHandle, _peristKeyInCsp);
            }
        }

        private SafeProvHandle SafeProvHandle
        {
            get
            {
                if (_safeProvHandle == null)
                {
                    lock (_parameters)
                    {
                        if (_safeProvHandle == null)
                        {
                            SafeProvHandle hProv = CapiHelper.CreateProvHandle(_parameters, _randomKeyContainer);

                            Debug.Assert(hProv != null);
                            Debug.Assert(!hProv.IsInvalid);
                            Debug.Assert(!hProv.IsClosed);

                            _safeProvHandle = hProv;
                        }
                    }

                    return _safeProvHandle;
                }

                return _safeProvHandle;
            }
        }

        private SafeKeyHandle SafeKeyHandle
        {
            get
            {
                if (_safeKeyHandle == null)
                {
                    lock (_parameters)
                    {
                        if (_safeKeyHandle == null)
                        {
                            SafeKeyHandle hKey = CapiHelper.GetKeyPairHelper(
                                CapiHelper.CspAlgorithmType.Gost2001,
                                _parameters,
                                GostConstants.GOST_3410EL_SIZE,
                                SafeProvHandle);

                            Debug.Assert(hKey != null);
                            Debug.Assert(!hKey.IsInvalid);
                            Debug.Assert(!hKey.IsClosed);

                            _safeKeyHandle = hKey;
                            _peristKeyInCsp = true;
                        }
                    }
                }

                return _safeKeyHandle;
            }
        }

        /// <summary>
        /// Получает значение, указывающее, не содержит ли объект 
        /// <see cref="Gost3410CryptoServiceProvider"/>
        /// только открытый ключ.
        /// </summary>
        /// 
        /// <value>
        /// <see langword="true"/>, если 
        /// <see cref="Gost3410CryptoServiceProvider"/> содержит только 
        /// открытый ключ, <see langword="false"/> - иначе.
        /// </value>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public bool PublicOnly
        {
            [SecuritySafeCritical]
            get
            {
                // Я так и не смог разобраться как MS хранят (или 
                // все-таки получают) этот флаг, но все равно у нас
                // нет официального способа его получения. Поэтому 
                // просто его храним.
                GetKeyPair();
                return _publicOnly;
            }
        }

        /// <summary> 
        /// Возвращает или устанавливает флаг того, что ключ должен храниться 
        /// в STORE ключей компьютера, а не в профиле пользователя.
        /// </summary>
        /// 
        /// <value>
        /// <see langword="true"/>, если ключ должен храниться в банке ключей 
        /// компьютера, <see langword="false"/> - иначе.
        /// </value>
        /// 
        /// <remarks><para>Данный флаг устанавливает использование ключей из
        /// STORE пользователя или компьютера при открытии ключей без 
        /// указания данного флага. Установка данного флага эквивалентна
        /// передаче установке флага 
        /// <see cref="CspProviderFlags.UseMachineKeyStore"/>
        /// в <see cref="CspParameters"/>. Свойство <c>UseMachineKeyStore</c>
        /// устанавливается для всего кода в текущем домене, в то время как 
        /// <see cref="CspParameters"/> применимо только к объекту на который
        /// он ссылается. Установка/сброс данного флага полезна при 
        /// имперсонализации или работе без загруженного профиля пользователя.
        /// </para>
        /// 
        /// <para>При инициализации объекта через конструктор 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// будут использованы именно эти параметры, в независимости от
        /// флага <see cref="UseMachineKeyStore"/>. По умолчанию значение
        /// флага из 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// устанавливется в использование ключей из хранилищи пользователя.
        /// Для использования ключей из хранилища компьютера при использовании
        /// конструктора 
        /// <see cref="Gost3410CryptoServiceProvider(CspParameters)"/>
        /// необходимо установить флаг <see cref="CspParameters.Flags"/>:
        /// <see cref="CspProviderFlags.UseMachineKeyStore"/>.
        /// </para>
        /// </remarks>
        public static bool UseMachineKeyStore
        {
            get
            {
                return (s_useMachineKeyStore == CspProviderFlags.UseMachineKeyStore);
            }
            set
            {
                s_useMachineKeyStore = (value ? CspProviderFlags.UseMachineKeyStore : 0);
            }
        }

        /// <summary>
        /// Создание ключа согласования (agree ключа).
        /// </summary>
        /// 
        /// <param name="alg">Открытый ключ получателя.</param>
        /// 
        /// <returns>Ключ согласования <see cref="GostSharedSecretAlgorithm"/> 
        /// для шифрования ключевой информации.</returns>
        /// 
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        public override GostSharedSecretAlgorithm CreateAgree(
            Gost3410Parameters alg)
        {

            //Получаем собственный ключ.
            GetKeyPair();

            //Превращаем его в объект для экспорта.
            Gost3410CspObject obj1 = new Gost3410CspObject(alg);

            return new GostSharedSecretCryptoServiceProvider(_safeKeyHandle,
                _safeProvHandle, obj1, CspAlgorithmType.Gost2001);
        }

        /// <summary>
        /// Получение/установка сертификата в конейнер.
        /// </summary>
        /// 
        /// <argnullset />
        /// 
        /// <unmanagedperm action="Demand" />
        /// <value>Возвращается хранимый сертификат или <see langword="null"/>,
        /// если сертификат в контейнере отсутствует.</value>
        public byte[] ContainerCertificate
        {
            [SecuritySafeCritical]
            get
            {
                byte[] rawData = CapiHelper.GetContainerCertificate(
                    SafeKeyHandle);
                return rawData;
            }
            [SecuritySafeCritical]
            set
            {
                if (value == null)
                    throw new ArgumentNullException("value");
                byte[] rawData = value;

                CapiHelper.SetKeyParameter(SafeKeyHandle,
                    GostConstants.KP_CERTIFICATE, rawData);
            }
        }

        /// <summary>
        /// Установка пароля доступа к контейнеру.
        /// </summary>
        /// 
        /// <param name="password">Пароль доступа к контейнеру.</param>
        /// 
        /// <remarks><para>Если ключ уже загружен в память, то поведение 
        /// данной функции зависит от провайдера, обычно проверяется 
        /// соответствие передаваемого пароля и пароля
        /// доступа на контейнер.</para> 
        /// <para>Если ключ не был загружен в память, данная функция
        /// не проверяет корректность вводимого пароля, а только 
        /// запоминает его. Проверка правильности введенного пароля
        /// будет происходить при доступе к ключу, например при
        /// операции подписи. </para></remarks>
        public void SetContainerPassword(SecureString password)
        {
            //Специально не документируем поведение при password == null
            //комментарий см. CPUtils.SetPin
            if (PublicOnly)
            {
                throw new CryptographicException(
                    SR.Cryptography_CSP_NoPrivateKey);
            }
            GetKeyPair();
            CapiHelper.SetPin(_safeProvHandle, password, this._keySpec);
        }

        /// <summary>
        /// Предварительная загрузка контейнера в память.
        /// </summary>
        /// 
        /// <cspversions><exclude version="20"/></cspversions>
        public void PreloadContainer()
        {
            if (PublicOnly)
            {
                throw new CryptographicException(
                    SR.Cryptography_CSP_NoPrivateKey);
            }
            GetKeyPair();
            CapiHelper.GetHCryptProv(_safeProvHandle);
        }

        /// <summary>
        /// Вывод диалогового окна выбора контейнера и получение 
        /// имени выбранного контейнера
        /// </summary>
        /// 
        /// <param name="fullyQualifiedContainerName">Вернуть полностью
        /// кваллифицированное имя контейнера.</param>
        /// <param name="machine">Использовать локальное хранилище
        /// компьютера (<see langword="true"/>) или пользователя
        /// (<see langword="true"/>).</param>
        /// <param name="parent">HWND родительского окна или IntPtr.Zero,
        /// для выдачи окна без родителя.</param>
        /// 
        /// <returns>Строку имени контейнера.</returns>
        public static string SelectContainer(bool fullyQualifiedContainerName,
            bool machine, IntPtr parent)
        {
            return CapiHelper.SelectContainer(fullyQualifiedContainerName,
                machine, parent, GostConstants.PROV_GOST_2012_256);
        }


        /// <summary>
        /// Генерация ключевой пары.
        /// </summary>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        /// <containerperm flag="Open">Для открытия существующего 
        /// контейнера.</containerperm>
        /// <containerperm flag="Create">Для создания контейнера с заданным
        /// (не случаыным именем).</containerperm>
        private void GetKeyPair()
        {
            // Force-read the SafeKeyHandle property, which will summon it into existence.
            SafeKeyHandle localHandle = SafeKeyHandle;
            Debug.Assert(localHandle != null);
        }

        /// <summary>
        /// Проверка, что переданные параметры, являются параметрами
        /// только открытого ключа.
        /// </summary>
        /// 
        /// <param name="gostParams">Проверяемые параметры.</param>
        /// 
        /// <returns><see langword="true"/>, если параметры не содержат, секретного 
        /// ключа</returns>
        private static bool IsPublic(Gost3410Parameters gostParams)
        {
            return (gostParams.PrivateKey == null);
        }

        /// <summary>
        /// Проверка, что байтовый массив представляет собой
        /// BLOB открытого ключа алгоритма ГОСТ Р 34.10
        /// </summary>
        /// <param name="keyBlob">Проверяемый BLOB.</param>
        /// <returns><see langword="true"/>, если похоже на BLOB ГОСТ Р 34.10 
        /// открытого ключа, <see langword="false"/> во всех остальных 
        /// случаях.</returns>
        /// <argnull name="keyBlob" />
        private static bool IsPublic(byte[] keyBlob)
        {
            // BYTE bType       0
            // BYTE bVersion    1
            // WORD reserved    2
            // ALG_ID aiKeyAlg  4
            // DWORD magic      8
            if (keyBlob == null) throw new ArgumentNullException("keyBlob");
            if (keyBlob[0] != GostConstants.PUBLICKEYBLOB || keyBlob.Length < 12) return false;
            byte[] magic = BitConverter.GetBytes(GostConstants.GR3410_1_MAGIC);
            if (magic[0] != keyBlob[8] || magic[1] != keyBlob[9] || magic[2] != keyBlob[10]
                || magic[3] != keyBlob[11]) return false;
            return true;
        }

        ///// <summary>
        ///// Шаг хеширования.
        ///// </summary>
        ///// 
        ///// <param name="hashAlgorithm">HashAlgorithmName</param>
        ///// <param name="data">Массив с хешируемыми данними.</param>
        ///// <param name="offset">Начало хешируемого блока в массиве.</param>
        ///// <param name="count">Размер хешируемого блока.</param>
        ///// 
        ///// <exception cref="CryptographicException">При ошибках на native
        ///// уровне.</exception>
        //[SecurityCritical]
        //protected override byte[] HashData(byte[] data, int offset, int count, HashAlgorithmName hashAlgorithm)
        //{
        //    CapiHelper.CryptHashData(this.SafeHashHandle, data, count, 0);
        //    return CapiHelper.EndHash(this.SafeHashHandle);
        //}

        /// <summary>
        /// This method helps Acquire the default CSP and avoids the need for static SafeProvHandle
        /// in CapiHelper class
        /// </summary>
        private SafeProvHandle AcquireSafeProviderHandle()
        {
            SafeProvHandle safeProvHandleTemp;
            CapiHelper.AcquireCsp(new CspParameters(GostConstants.PROV_GOST_2001_DH), out safeProvHandleTemp);
            return safeProvHandleTemp;
        }
    }
}
