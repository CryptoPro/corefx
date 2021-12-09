// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.ComponentModel;

namespace System.Security.Cryptography
{
    using System.Diagnostics;
    using Internal.NativeCrypto;

    [EditorBrowsable(EditorBrowsableState.Never)]
    public sealed class Gost28147CryptoServiceProvider : Gost28147
    {
        /// <summary>
        /// Размер ключа 256 бит.
        /// </summary>
        internal const int DefKeySize = 256;
        /// <summary>
        /// Размер блока 64 бита.
        /// </summary>
        internal const int DefBlockSize = 64;
        /// <summary>
        /// Размер зацепления 64 бита.
        /// </summary>
        internal const int DefFeedbackSize = 64;
        /// <summary>
        /// Размер синхропосылки 64 бита.
        /// </summary>
        internal const int IVSize = 64;

        private const int BitsPerByte = 8;

        /// <summary>
        /// Хэндл провайдера
        /// </summary>
        private SafeProvHandle _safeProvHandle;

        /// <summary>
        /// Хэндл ключа
        /// </summary>
        private SafeKeyHandle _safeKeyHandle;

        /// <summary>
        /// Параметры криптопровайдера
        /// </summary>
        private CspParameters _parameters;

        /// <summary>
        /// Получение HANDLE провайдера
        /// </summary>
        private SafeProvHandle SafeProvHandle
        {
            get
            {
                if (_safeProvHandle.IsInvalid)
                {
                    CapiHelper.AcquireCsp(_parameters, out SafeProvHandle hProv);

                    Debug.Assert(hProv != null);
                    Debug.Assert(!hProv.IsInvalid);
                    Debug.Assert(!hProv.IsClosed);

                    _safeProvHandle = hProv;

                    return _safeProvHandle;
                }

                return _safeProvHandle;
            }
        }

        /// <summary>
        /// Получение текущего (не дубликата) HANDLE ключа.
        /// </summary>
        ///
        /// <unmanagedperm action="LinkDemand" />
        ///
        /// <remarks><para>
        /// Значение <code>KP_PADDING</code>, <code>KP_MODE</code> и аналогичных
        /// для хендла не совпадает с
        /// <see cref="System.Security.Cryptography.SymmetricAlgorithm.Padding"/>,
        /// <see cref="System.Security.Cryptography.SymmetricAlgorithm.Mode"/>.
        /// </para></remarks>
        internal SafeKeyHandle SafeKeyHandle
        {
            [SecurityCritical]
            get
            {
                if (_safeKeyHandle.IsInvalid)
                    GenerateKey();
                return _safeKeyHandle;
            }
        }

        /// <summary>
        /// Получение текущего HANDLE провайдера без AddRef.
        /// </summary>
        ///
        /// <unmanagedperm action="LinkDemand" />
        internal SafeProvHandle InternalProvHandle
        {
            get
            {
                // Проверяем именно ключ.
                if (_safeKeyHandle.IsInvalid)
                    GenerateKey();
                return _safeProvHandle;
            }
        }

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

        public Gost28147CryptoServiceProvider()
        {
            Mode = CipherMode.CFB;
            Padding = PaddingMode.None;
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            _safeProvHandle = SafeProvHandle.InvalidHandle;

            _parameters = new CspParameters(GostConstants.PROV_GOST_2001_DH);
        }

        public Gost28147CryptoServiceProvider(CspParameters parameters)
        {
            Mode = CipherMode.CFB;
            Padding = PaddingMode.None;
            _safeKeyHandle = SafeKeyHandle.InvalidHandle;
            _safeProvHandle = SafeProvHandle.InvalidHandle;

            _parameters = new CspParameters(parameters.ProviderType);
        }

        /// <summary>
        /// Создание объекта симметричного шифрования по HANDLE ключа.
        /// </summary>
        ///
        /// <remarks><para>При создании объекта симметричного шифрования
        /// параметры ключа устанавливаются в свои значения по умолчанию:</para>
        ///
        /// <table>
        /// <tr><th>Параметр</th><th>Значение</th></tr>
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.IV"/></td>
        /// <td><see langword="null"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Mode"/></td>
        /// <td><see cref="System.Security.Cryptography.CipherMode.CFB"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Padding"/></td>
        /// <td><see cref="System.Security.Cryptography.PaddingMode.None"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.KeySize"/></td>
        /// <td><c>256</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.FeedbackSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.BlockSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// </table>
        ///
        /// <para>Класс становится владельцем ДУБЛЯ ключа и закрывает
        /// HANDLE при закрытии класса, HANDLE провайдера не дублируется,
        /// но увеличивается счетчик его использования (DangerousAddRef).
        /// </para>
        /// </remarks>
        ///
        /// <param name="keyHandle">HANDLE симметричного ключа.</param>
        /// <param name="providerHandle">HANDLE провайдера.</param>
        ///
        /// <argnull name="keyHandle" />
        /// <exception cref="ArgumentException">Параметр <c>keyHandle</c>
        /// содержит ключ не алгоритма ГОСТ 28147.
        /// </exception>
        ///
        /// <unmanagedperm action="Demand" />
        public Gost28147CryptoServiceProvider(IntPtr keyHandle, IntPtr providerHandle)
            : this()
        {
            _safeProvHandle = new SafeProvHandle(providerHandle, true);
            _safeKeyHandle = CapiHelper.DuplicateKey(
                keyHandle,
                _safeProvHandle);
            int algid = CapiHelper.GetKeyParamDw(_safeKeyHandle, Constants.CLR_ALGID);
            if (algid != GostConstants.CALG_G28147)
                throw new ArgumentException("algid");
        }

        /// <summary>
        /// Создание объекта симметричного шифрования по HANDLE ключа.
        /// </summary>
        ///
        /// <remarks><para>При создании объекта симметричного шифрования
        /// параметры ключа устанавливаются в свои значения по умолчанию:</para>
        ///
        /// <table>
        /// <tr><th>Параметр</th><th>Значение</th></tr>
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.IV"/></td>
        /// <td><see langword="null"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Mode"/></td>
        /// <td><see cref="System.Security.Cryptography.CipherMode.CFB"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.Padding"/></td>
        /// <td><see cref="System.Security.Cryptography.PaddingMode.None"/></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.KeySize"/></td>
        /// <td><c>256</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.FeedbackSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// <tr><td><see cref="System.Security.Cryptography.SymmetricAlgorithm.BlockSize"/></td>
        /// <td><c>64</c></td></tr>
        ///
        /// </table>
        ///
        /// <para>Класс становится владельцем ДУБЛЯ ключа и закрывает
        /// HANDLE при закрытии класса, HANDLE провайдера не дублируется,
        /// но увеличивается счетчик его использования (DangerousAddRef).
        /// </para>
        /// </remarks>
        ///
        /// <param name="keyHandle">HANDLE симметричного ключа.</param>
        /// <param name="provHandle">HANDLE провайдера.</param>
        ///
        /// <argnull name="keyHandle" />
        /// <exception cref="ArgumentException">Параметр <c>keyHandle</c>
        /// содержит ключ не алгоритма ГОСТ 28147.
        /// </exception>
        ///
        /// <unmanagedperm action="LinkDemand" />
        internal Gost28147CryptoServiceProvider(SafeKeyHandle keyHandle,
            SafeProvHandle provHandle) : this()
        {
            // корректность параметров CSP проверяется
            // при создании ecnryptor
            if (keyHandle == null)
                throw new ArgumentNullException("keyHandle");
            // Проверяем наличие провайдера поддерживающего ГОСТ 28147.
            // А куда CSP денется?
            //if (!CPUtils.HasAlgorithm(Constants.CALG_G28147, 0))
            //{
            //    throw new CryptographicException(
            //        Resources.Cryptography_CSP_AlgorithmNotAvailable);
            //}
            _safeKeyHandle = CapiHelper.DuplicateKey(
                keyHandle.DangerousGetHandle(),
                provHandle);

            bool succeded = false;
            provHandle.DangerousAddRef(ref succeded);
            _safeProvHandle = provHandle;

            int algid = CapiHelper.GetKeyParamDw(_safeKeyHandle, Constants.CLR_ALGID);
            if (algid != GostConstants.CALG_G28147)
                throw new ArgumentException("keyHandle");
            // KeySizeValue устанавливается в базовом классе.
            // FeedbackSizeValue устанавливается в базовом классе.
            // BlockSizeValue устанавливается в базовом классе.
        }        

        public override ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV)
        {
            throw new NotImplementedException();
        }

        public override ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV)
        {
            throw new NotImplementedException();
        }

        public override ICryptoTransform CreateEncryptor()
        {
            return CreateTransform(true);
        }

        public override ICryptoTransform CreateDecryptor()
        {
            return CreateTransform(false);
        }

        public override void GenerateIV()
        {
            using (var rng = new GostRngCryptoServiceProvider())
            {
                IVValue = new byte[IVSize / BitsPerByte];
                rng.GetBytes(IVValue);
            }
        }

        public override void GenerateKey()
        {
            CapiHelper.GenerateKey(SafeProvHandle,
                GostConstants.CALG_G28147, CspProviderFlags.NoFlags,
                GostConstants.G28147_KEYLEN * BitsPerByte, out _safeKeyHandle);
            KeyValue = null;
            KeySizeValue = GostConstants.G28147_KEYLEN * BitsPerByte;
        }

        public override byte[] ComputeHash(HashAlgorithm hash)
        {
            throw new NotImplementedException();
        }

        /// <summary>
        /// Экспортирует (шифрует) секретный ключ.
        /// </summary>
        /// <param name="prov">Шифруемый ключ.</param>
        /// <param name="method">Алгоритм экспорта ключа.</param>
        /// <returns>Зашифрованный симметричный ключ</returns>
        public override byte[] Wrap(Gost28147 prov, GostKeyWrapMethod method)
        {
            SafeKeyHandle hSimmKey = ((Gost28147CryptoServiceProvider)prov).SafeKeyHandle;
            int calg = GostConstants.CALG_SIMPLE_EXPORT;
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
                calg = GostConstants.CALG_PRO_EXPORT;
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
                calg = GostConstants.CALG_PRO12_EXPORT;
            else if (method != GostKeyWrapMethod.GostKeyWrap)
                throw new ArgumentOutOfRangeException("method");
            byte[] ret = null;
            // Сохраняем состояние algid GOST12147
            using (SafeKeyHandle hExpKey = CapiHelper.DuplicateKey(
                SafeKeyHandle.DangerousGetHandle(),
                SafeProvHandle))
            {
                CapiHelper.SetKeyParameter(hExpKey, GostConstants.KP_ALGID, calg);
                CapiHelper.SetKeyParameter(hExpKey, GostConstants.KP_IV, IV);

                GostWrappedKeyObject wrappedKey = new GostWrappedKeyObject();
                CapiHelper.ExportSessionWrapedKey(hSimmKey,
                    hExpKey, wrappedKey);

                ret = wrappedKey.GetXmlWrappedKey();
            }
            return ret;
        }

        /// <summary>
        /// Импортирует (дешифрует) секретный ключ.
        /// </summary>
        /// <param name="wrapped">Зашифрованный секретный ключ.</param>
        /// <param name="method">Алгоритм экспорта ключа.</param>
        public override SymmetricAlgorithm Unwrap(byte[] wrapped, GostKeyWrapMethod method)
        {
            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);
            int calg = GostConstants.CALG_SIMPLE_EXPORT;
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
                calg = GostConstants.CALG_PRO_EXPORT;
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
                calg = GostConstants.CALG_PRO12_EXPORT;
            else if (method != GostKeyWrapMethod.GostKeyWrap)
                throw new ArgumentOutOfRangeException("method");
            SymmetricAlgorithm ret = null;
            // Сохраняем состояние algid GOST12147
            using (SafeKeyHandle hExpKey = CapiHelper.DuplicateKey(
                SafeKeyHandle.DangerousGetHandle(),
                SafeProvHandle))
            {
                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID, calg);
                SafeKeyHandle simmKey = SafeKeyHandle.InvalidHandle;
                CapiHelper.AcquireCsp(_parameters, out SafeProvHandle hProv);

                CapiHelper.ImportSessionWrappedKey(
                    hProv, CspProviderFlags.NoFlags,
                    gwk, hExpKey, ref simmKey);
                ret = new Gost28147CryptoServiceProvider(simmKey, hProv);
            }
            return ret;
        }

        private ICryptoTransform CreateTransform(bool encrypting)
        {
            // При обращении к KeyHandle возможна генерация ключа.
            SafeKeyHandle hDupKey = CapiHelper.DuplicateKey(
                SafeKeyHandle.DangerousGetHandle(),
                SafeProvHandle);

            // Добавляем ссылку на провайдер
            bool success = false;
            SafeProvHandle.DangerousAddRef(ref success);

            // При обращении к IV возможна генерация синхропосылки.

            return CreateTransformCore(
                SafeProvHandle,
                hDupKey, 
                base.ModeValue, 
                base.PaddingValue, 
                IV, 
                base.BlockSizeValue, 
                base.FeedbackSizeValue, 
                encrypting);
        }

        private static ICryptoTransform CreateTransformCore(
            SafeProvHandle hProv,
            SafeKeyHandle hKey,
            CipherMode mode,
            PaddingMode padding,
            byte[] rgbIV,
            int blockSize,
            int feedbackSize, 
            bool encrypting)
        {
            //#Q_ ToDo выжечь огнём этот ад с двумя масивами для передачи параметров в GostCryptoAPITransform
            // переделать на словарь, или в идеале просто явно передавать параметры через структуру, но не этот ужас

            int num1 = 0;
            int[] numArray1 = new int[10];
            object[] objArray1 = new object[10];

            // Не поддерживаем CTS. Выдаем приличное исключение.
            if (mode == CipherMode.CTS)
                throw new ArgumentException(
                    SR.Argument_InvalidValue, nameof(mode));  //SR.Cryptography_CSP_CTSNotSupported
            // Поддерживаем только правильные пары Padding - mode
            if (mode == CipherMode.OFB || mode == CipherMode.CFB)
            {
                if (padding != PaddingMode.None)
                    throw new CryptographicException(
                    SR.Cryptography_InvalidPaddingMode);
            }
            // Сбрасываем Pading, мы сами его поддерживаем.
            numArray1[num1] = GostConstants.KP_PADDING;
            objArray1[num1] = GostConstants.WINCRYPT_PADDING_ZERO;
            num1++;

            // Поддерживаем только CFB с feedback по ГОСТ.
            if ((mode == CipherMode.CFB)
                && (feedbackSize != DefFeedbackSize))
            {
                throw new ArgumentException(SR.Argument_InvalidValue, nameof(feedbackSize));
            }
            // Нет ключа, генерим.
            if (hKey == null)
            {
                CapiHelper.GenerateKey(hProv,
                    GostConstants.CALG_G28147,
                    CspProviderFlags.NoFlags, GostConstants.G28147_KEYLEN * BitsPerByte,
                    out hKey);
            }
            // Ключ приходит как Handle, поэтому длины не проверяем.

            // Mode ставим всегда, так как при создании ключа по Handle
            // он может быть другим.
            numArray1[num1] = GostConstants.KP_MODE;
            objArray1[num1] = mode;
            num1++;

            // Для всех mode кроме ECB требуется синхропосылка. Устанавливаем.
            if (mode != CipherMode.ECB)
            {
                // Если ее нет, то генерим.
                if (rgbIV == null)
                {
                    if (!encrypting)
                    {
                        // при расшифровании IV должен быть задан
                        throw new CryptographicException(SR.Cryptography_MissingIV);
                    }
                    // Не используем GenerateIV: классовая и переданная
                    // IV могут отличаться.
                        rgbIV = new byte[IVSize / 8];
                    using (var rng = new GostRngCryptoServiceProvider(hProv))
                    {
                        rng.GetBytes(rgbIV);
                    }
                }
                // проверяем достаточность по длине.
                if (rgbIV.Length < IVSize / BitsPerByte)
                {
                    throw new CryptographicException(
                        SR.Cryptography_InvalidIVSize);
                }
                numArray1[num1] = GostConstants.KP_SV;
                objArray1[num1] = rgbIV;
                num1++;
            }

            // Можно еще установить для CFB количество бит зацепления, но
            // оно всегда равно 64 и его установка не поддерживается CSP.
            return new GostCryptoAPITransform(num1, numArray1, objArray1, hKey, hProv,
                padding, mode, blockSize, encrypting);
        }

        ///// <summary>
        ///// Создание объекта криптографического преобразования: шифратора.
        ///// </summary>
        ///// 
        ///// <param name="mode">Режим шифрования</param>
        ///// <param name="rgbIV">Синхропосылка</param>
        ///// <param name="feedbackSize">Размер блока зацепления.</param>
        ///// <param name="encryptMode">Режим зашифрования или 
        ///// расшифрования</param>
        ///// <param name="hKey">Ключ</param>
        ///// 
        ///// <returns>Шифратор</returns>
        ///// 
        ///// <remarks><para>Функция не изменяет значения ключа, 
        ///// синхропосылки, mode, feedbackSize собственного объекта, да же при
        ///// генерации этих значений внутри функции.</para>
        ///// <para>Значения Padding и размера блока берутся из основного 
        ///// объекта.</para>
        ///// <para>Transform становится владельцем ключа и, после использования,
        ///// осуществляет его уничтожение.</para>
        ///// </remarks>
        ///// 
        ///// <exception cref="CryptographicException"><c>mode</c> == 
        ///// <see cref="CipherMode"/>.CTS; при <see cref="PaddingMode"/> не 
        ///// соответствующем <c>mode</c>; для режима CFB при неправильно 
        ///// заданном <c>feedbackSize</c>; при недостаточной длине 
        ///// <c>rgbIV</c> в соответствующих режимах.</exception>
        ///// 
        ///// <unmanagedperm action="LinkDemand" />
        //private ICryptoTransform _NewEncryptor(SafeKeyHandle hKey,
        //    CipherMode mode, byte[] rgbIV,
        //    int feedbackSize, CryptoAPITransformMode encryptMode)
        //{
        //    int num1 = 0;
        //    int[] numArray1 = new int[10];
        //    object[] objArray1 = new object[10];

        //    // Не поддерживаем CTS. Выдаем приличное исключение.
        //    if (mode == CipherMode.CTS)
        //        throw new CryptographicException(
        //            Resources.Cryptography_CSP_CTSNotSupported);
        //    // Поддерживаем только правильные пары Padding - mode
        //    if (mode == CipherMode.OFB || mode == CipherMode.CFB)
        //    {
        //        if (Padding != PaddingMode.None)
        //            throw new CryptographicException(
        //            Resources.Cryptography_InvalidPaddingMode);
        //    }
        //    // Сбрасываем Pading, мы сами его поддерживаем.
        //    numArray1[num1] = Constants.KP_PADDING;
        //    objArray1[num1] = Constants.WINCRYPT_PADDING_ZERO;
        //    num1++;

        //    // Поддерживаем только CFB с feedback по ГОСТ.
        //    if ((mode == CipherMode.CFB)
        //        && (feedbackSize != DefFeedbackSize))
        //    {
        //        throw new CryptographicException(
        //            Resources.Cryptography_CSP_CFBSizeNotSupported);
        //    }
        //    // Нет ключа, генерим.
        //    if (hKey == null)
        //    {
        //        hKey = SafeKeyHandleCP.InvalidHandle;
        //        COMCryptography.GenerateKey(CPUtils.StaticGost2001ProvHandle,
        //            Constants.CALG_G28147,
        //            CspProviderFlags.NoFlags, Constants.G28147_KEYLEN * 8,
        //            ref hKey);
        //    }
        //    // Ключ приходит как Handle, поэтому длины не проверяем.

        //    // Mode ставим всегда, так как при создании ключа по Handle
        //    // он может быть другим.
        //    numArray1[num1] = Constants.KP_MODE;
        //    objArray1[num1] = mode;
        //    num1++;

        //    // Для всех mode кроме ECB требуется синхропосылка. Устанавливаем.
        //    if (mode != CipherMode.ECB)
        //    {
        //        // Если ее нет, то генерим.
        //        if (rgbIV == null)
        //        {
        //            // Не используем GenerateIV: классовая и переданная 
        //            // IV могут отличаться.
        //            rgbIV = new byte[IVSize / 8];
        //            CPUtils.StaticRandomNumberGenerator.GetBytes(rgbIV);
        //        }
        //        // и проверяем достаточность по длине.
        //        if (rgbIV.Length < IVSize / 8)
        //        {
        //            throw new CryptographicException(
        //                Resources.Cryptography_InvalidIVSize);
        //        }
        //        numArray1[num1] = Constants.KP_SV;
        //        objArray1[num1] = rgbIV;
        //        num1++;
        //    }
        //    // Можно еще установить для CFB количество бит зацепления, но
        //    // оно всегда равно 64 и его установка не поддерживается CSP.
        //    return new CPCryptoAPITransform(num1, numArray1, objArray1, hKey,
        //        base.PaddingValue, mode, base.BlockSizeValue, encryptMode);
        //}
    }    
}
