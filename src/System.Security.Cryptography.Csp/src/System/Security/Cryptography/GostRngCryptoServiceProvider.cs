namespace System.Security.Cryptography
{
    using Internal.NativeCrypto;

    class GostRngCryptoServiceProvider : RandomNumberGenerator
    {
        SafeProvHandle m_safeProvHandle;

        public GostRngCryptoServiceProvider()
        {
            CspParameters gostParameters = new CspParameters(GostConstants.PROV_GOST_2001_DH);
            m_safeProvHandle = AcquireSafeProviderHandle(gostParameters);
        }

        public GostRngCryptoServiceProvider(CspParameters cspParams)
        {
            m_safeProvHandle = AcquireSafeProviderHandle(cspParams);
        }

        public GostRngCryptoServiceProvider(SafeProvHandle hProv)
        {
            bool successed = false;
            hProv.DangerousAddRef(ref successed);
            m_safeProvHandle = hProv;
        }

        public override void GetBytes(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException(nameof(data));
            CapiHelper.GenerateRandomBytes(m_safeProvHandle, data);
        }

        /// <summary>
        /// This method helps Acquire the default CSP and avoids the need for static SafeProvHandle
        /// in CapiHelper class
        /// </summary>
        private SafeProvHandle AcquireSafeProviderHandle(CspParameters cspParams)
        {
            SafeProvHandle safeProvHandleTemp;
            CapiHelper.AcquireCsp(cspParams, out safeProvHandleTemp);
            return safeProvHandleTemp;
        }

        protected override void Dispose(bool disposing)
        {
            base.Dispose(disposing);

            if (disposing)
            {
                m_safeProvHandle.Dispose();
            }
        }
    }
}
