using System.Security.Permissions;
using System.Runtime.InteropServices;
using static Internal.NativeCrypto.CapiHelper;
using Internal.NativeCrypto;

namespace System.Security.Cryptography
{
    /// <summary>
    /// Реализация ключа согласования через криптопровайдер.
    /// </summary>
    /// 
    /// <remarks>
    /// Ключ согласования используется для шифрования/расшифрования 
    /// секретных симметричных ключей.
    /// </remarks>
    /// 
    /// <doc-sample path="Simple\Encrypt" name="gEncryptFileAgree">Пример 
    /// использования agree ключа.</doc-sample>
    /// 
    /// <cspversions />
    public sealed class GostSharedSecretCryptoServiceProvider :
        GostSharedSecretAlgorithm
    {
        /// <summary>
        /// Рабочий HANDLE секретного ключа.
        /// </summary>
        private SafeKeyHandle _safeKeyHandle;
        /// <summary>
        /// Рабочий HANDLE провайдера, в котором находится ключ.
        /// </summary>
        private SafeProvHandle _safeProvHandle;
        /// <summary>
        /// Открытый ключ.
        /// </summary>
        private Gost3410CspObject _publicObject;

        /// <summary>
        /// Тип используемого алгоритма
        /// </summary>
        private CspAlgorithmType _algType;

        internal GostSharedSecretCryptoServiceProvider()
        {
            throw new NotSupportedException();
        }

        /// <summary>
        /// Создание распределенного секрета по HANDLE ключа в CSP
        /// </summary>
        /// <param name="key">HANDLE секретного ключа в CSP.</param>
        /// <param name="prov">HANDLE провайдера (CSP), внутри которого
        /// существует ключ.</param>
        /// <param name="publicObject">Открытый ключ.</param>
        /// <param name="algType"></param>
        /// 
        /// <argnull name="key" />
        /// <argnull name="prov" />
        /// <argnull name="publicObject" />
        /// <exception cref="CryptographicException">При ошибках на native
        /// уровне.</exception>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal GostSharedSecretCryptoServiceProvider(SafeKeyHandle key,
        SafeProvHandle prov, Gost3410CspObject publicObject, CspAlgorithmType algType)
        {
            if (key == null)
                throw new ArgumentNullException("key");
            if (prov == null)
                throw new ArgumentNullException("prov");
            if (publicObject == null)
                throw new ArgumentNullException("publicObject");
            // В связи с отсутствием DuplicateKey, используем грязный хак
            _safeKeyHandle = key;
            bool isinc = false;
            _safeKeyHandle.DangerousAddRef(ref isinc);
            _safeProvHandle = prov;
            _safeProvHandle.DangerousAddRef(ref isinc);
            _publicObject = publicObject;
            _algType = algType;
        }

        /// <summary>
        /// Зашифрование (экспорт) симметричного ключа.
        /// </summary>
        /// 
        /// <remarks><para>Формат зашифрованного ключа зависит от метода 
        /// зашифрования; для <see cref="GostKeyWrapMethod.GostKeyWrap"/> и 
        /// <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>
        /// формат зашифрованного ключа определяется функцией 
        /// <see cref="GostWrappedKey.GetXmlWrappedKey"/>.</para>
        /// 
        /// <para>При зашифровании ключа используется синхропосылка
        /// заданная <see cref="SymmetricAlgorithm.IV"/></para>
        /// </remarks>
        /// 
        /// <param name="alg">Объект класса <see cref="SymmetricAlgorithm"/>, 
        /// содержащий симметричный ключ.</param>
        /// <param name="method">Алгоритм экспорта ключа.</param>
        /// 
        /// <returns>Зашифрованный симметричный ключ.</returns>
        /// 
        /// <seealso cref="GostWrappedKey"/>
        /// <seealso cref="GostSharedSecretCryptoServiceProvider.Unwrap"/>
#if SHARPEI_DESTINATION_FW40
        [SecuritySafeCritical]
#endif
        public override byte[] Wrap(SymmetricAlgorithm alg,
            GostKeyWrapMethod method)
        {
            Gost28147 gost = alg as Gost28147;
            if (gost == null)
            {
                throw new ArgumentException(nameof(alg));
            }
            Gost28147CryptoServiceProvider prov = gost as
                Gost28147CryptoServiceProvider;
            if (prov == null)
            {
                using (Gost28147CryptoServiceProvider p =
                    new Gost28147CryptoServiceProvider())
                {
                    return p.Wrap(prov, method);
                }
            }
            return Wrap(prov, method);
        }

        /// <summary>
        /// Wrap ключа Gost28147CryptoServiceProvider на agree.
        /// </summary>
        /// 
        /// <param name="prov">Шифруемый ключ</param>
        /// <param name="method">Метод зашифрования ключа.</param>
        /// 
        /// <returns>Зашифрованный симметричный ключ</returns>
        private byte[] Wrap(Gost28147CryptoServiceProvider prov,
            GostKeyWrapMethod method)
        {
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
                return CryptoProWrap(prov);
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
                return CryptoProWrap(prov, GostConstants.CALG_PRO12_EXPORT);
            else if (method == GostKeyWrapMethod.GostKeyWrap)
                return GostWrap(prov);
            else
                throw new ArgumentOutOfRangeException("method");
        }

        /// <summary>
        /// Wrap ключа Gost28147CryptoServiceProvider на agree
        /// по <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="prov">Шифруемый ключ.</param>
        /// <param name="calgProExport">CALG алгоритма экспорта крипто про</param>
        /// <returns>Зашифрованный симметричный ключ.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// на managed уровне.</exception>
        private byte[] CryptoProWrap(Gost28147CryptoServiceProvider prov, int calgProExport = GostConstants.CALG_PRO_EXPORT)
        {
            if (calgProExport != GostConstants.CALG_PRO_EXPORT && calgProExport != GostConstants.CALG_PRO12_EXPORT)
            {
                throw new ArgumentOutOfRangeException("calgProExport");
            }

            SafeKeyHandle hSimmKey = prov.SafeKeyHandle;
            GostWrappedKeyObject wrappedKey = new GostWrappedKeyObject();
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;

            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    calgProExport);

                CapiHelper.ExportSessionWrapedKey(hSimmKey,
                    hExpKey, wrappedKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }
            return wrappedKey.GetXmlWrappedKey();
        }


        /// <summary>
        /// Wrap ключа Gost28147CryptoServiceProvider на agree
        /// по <see cref="GostKeyWrapMethod.GostKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="prov">Шифруемый ключ.</param>
        /// 
        /// <returns>Зашифрованный симметричный ключ.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// на managed уровне.</exception>
        private byte[] GostWrap(Gost28147CryptoServiceProvider prov)
        {
            SafeKeyHandle hSimmKey = prov.SafeKeyHandle;
            GostWrappedKeyObject wrappedKey = new GostWrappedKeyObject();
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;

            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    GostConstants.CALG_SIMPLE_EXPORT);

                CapiHelper.ExportSessionWrapedKey(hSimmKey,
                    hExpKey, wrappedKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }
            return wrappedKey.GetXmlWrappedKey();
        }

        /// <summary>
        /// Расшифрование симметричного ключа.
        /// </summary>
        /// 
        /// <param name="wrapped">Зашифрованный секретный ключ.</param>
        /// <param name="method">Метод зашифрования ключа.</param>
        /// 
        /// <returns>Объект класса <see cref="SymmetricAlgorithm"/>, 
        /// содержащий расшифрованный закрытый ключ.</returns>
        /// 
        /// <remarks><para>Формат зашифрованного ключа зависит от метода 
        /// зашифрования; для <see cref="GostKeyWrapMethod.GostKeyWrap"/> и 
        /// <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>
        /// формат зашифрованного ключа определяется функцией 
        /// <see cref="GostWrappedKey.GetXmlWrappedKey"/>.</para>
        /// </remarks>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// на managed уровне.</exception>
#if SHARPEI_DESTINATION_FW40
        [SecuritySafeCritical]
#endif
        public override SymmetricAlgorithm Unwrap(byte[] wrapped,
            GostKeyWrapMethod method)
        {
            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);
            if (method == GostKeyWrapMethod.CryptoProKeyWrap)
            {
                return CryptoProUnwrap(wrapped, GostConstants.CALG_PRO_EXPORT);
            }
            else if (method == GostKeyWrapMethod.CryptoPro12KeyWrap)
            {
                // В случае с гостом 2012 мы не уверны, был ли экспорт на ProExport или ProExport12
                // из-за обратной совместимости (раньше шифровали на ProExport, теперь только на ProExport12). Попробуем оба варианата
                return CryptoProUnwrap(wrapped);
            }
            else if (method == GostKeyWrapMethod.GostKeyWrap)
            {
                return GostUnwrap(wrapped);
            }
            else
            {
                throw new ArgumentOutOfRangeException("method");
            }
        }

        /// <summary>
        /// Расшифрование симметричного ключа по
        /// по <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="wrapped">Зашифрованный секретный ключ.</param>
        /// <param name="calgProExport">OID алгоритма экспорта</param>
        /// <returns>Объект класса <see cref="SymmetricAlgorithm"/>, 
        /// содержащий расшифрованный закрытый ключ.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// на managed уровне.</exception>
        private SymmetricAlgorithm CryptoProUnwrap(byte[] wrapped, int calgProExport)
        {
            if (calgProExport != GostConstants.CALG_PRO_EXPORT && calgProExport != GostConstants.CALG_PRO12_EXPORT)
            {
                throw new ArgumentOutOfRangeException("calgProExport");
            }

            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);

            SafeKeyHandle simmKey = SafeKeyHandle.InvalidHandle;
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;
            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    calgProExport);

                CapiHelper.ImportSessionWrappedKey(_safeProvHandle,
                    CspProviderFlags.NoFlags, gwk, hExpKey, ref simmKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }

            return new Gost28147CryptoServiceProvider(simmKey, _safeProvHandle);
        }

        /// <summary>
        /// Расшифрование симметричного ключа по
        /// по <see cref="GostKeyWrapMethod.CryptoProKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="wrapped">Зашифрованный секретный ключ.</param>
        /// 
        /// <returns>Объект класса <see cref="SymmetricAlgorithm"/>, 
        /// содержащий расшифрованный закрытый ключ.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// на managed уровне.</exception>
        private SymmetricAlgorithm CryptoProUnwrap(byte[] wrapped)
        {
            try
            {
                return this.CryptoProUnwrap(wrapped, GostConstants.CALG_PRO12_EXPORT);
            }
            catch (CryptographicException ex)
            {
                if (Marshal.GetHRForException(ex) == -2146893819)
                {
                    // bad data - пробуем импорт на старом алгоритме
                    return this.CryptoProUnwrap(wrapped, GostConstants.CALG_PRO_EXPORT);
                }
                else
                {
                    throw;
                }
            }
        }

        /// <summary>
        /// Расшифрование симметричного ключа по
        /// по <see cref="GostKeyWrapMethod.GostKeyWrap"/>.
        /// </summary>
        /// 
        /// <param name="wrapped">Зашифрованный секретный ключ.</param>
        /// 
        /// <returns>Объект класса <see cref="SymmetricAlgorithm"/>, 
        /// содержащий расшифрованный закрытый ключ.</returns>
        /// 
        /// <exception cref="CryptographicException">При ошибках
        /// на managed уровне.</exception>
        private SymmetricAlgorithm GostUnwrap(byte[] wrapped)
        {
            GostWrappedKeyObject gwk = new GostWrappedKeyObject();
            gwk.SetByXmlWrappedKey(wrapped);

            SafeKeyHandle simmKey = SafeKeyHandle.InvalidHandle;
            SafeKeyHandle hExpKey = SafeKeyHandle.InvalidHandle;
            try
            {
                CapiHelper.ImportAndMakeSharedSecret(_safeProvHandle,
                    CspProviderFlags.NoFlags, _publicObject, _safeKeyHandle,
                    ref hExpKey, _algType);

                CapiHelper.SetKeyParamDw(hExpKey, GostConstants.KP_ALGID,
                    GostConstants.CALG_SIMPLE_EXPORT);

                CapiHelper.ImportSessionWrappedKey(_safeProvHandle,
                    CspProviderFlags.NoFlags, gwk, hExpKey, ref simmKey);
            }
            finally
            {
                if (!hExpKey.IsClosed)
                    hExpKey.Close();
            }

            return new Gost28147CryptoServiceProvider(simmKey, _safeProvHandle);
        }

        /// <summary>
        /// Получение текущего (не дубликата) HANDLE ключа.
        /// </summary>
        /// 
        /// <unmanagedperm action="LinkDemand" />
        internal SafeKeyHandle SafeKeyHandle
        {
            get
            {
                return _safeKeyHandle;
            }
        }

        /// <summary>
        /// Получение текущего (не дубликата) HANDLE ключа.
        /// </summary>
        /// 
        /// <unmanagedperm action="Demand" />
        public IntPtr KeyHandle
        {
            [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
            get
            {
                return SafeKeyHandle.DangerousGetHandle();
            }
        }

        /// <summary>
        /// Получение текущего HANDLE провайдера без изменения RefCount.
        /// </summary>
        /// 
        /// <unmanagedperm action="Demand" />
        public IntPtr ProviderHandle
        {
            [SecurityPermission(SecurityAction.Demand, Flags = SecurityPermissionFlag.UnmanagedCode)]
            get
            {
                return InternalProvHandle.DangerousGetHandle();
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
                return _safeProvHandle;
            }
        }

        /// <summary>
        /// Закрытие HANDLE ключа ассоциированного с ним.
        /// </summary>
        /// 
        /// <param name="disposing">Вызов из finalize.</param>
        protected override void Dispose(bool disposing)
        {
            if ((_safeKeyHandle != null) && !_safeKeyHandle.IsClosed)
            {
                _safeKeyHandle.DangerousRelease();
            }
            if ((_safeProvHandle != null) && !_safeProvHandle.IsClosed)
            {
                _safeProvHandle.DangerousRelease();
            }
            base.Dispose(disposing);
        }
    }
}
