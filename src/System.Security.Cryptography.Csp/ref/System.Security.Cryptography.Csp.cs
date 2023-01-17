// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.
// ------------------------------------------------------------------------------
// Changes to this file must follow the http://aka.ms/api-review process.
// ------------------------------------------------------------------------------

namespace System.Security.Cryptography
{
    public sealed partial class AesCryptoServiceProvider : System.Security.Cryptography.Aes
    {
        public AesCryptoServiceProvider() { }
        public override int BlockSize { get { throw null; } set { } }
        public override int FeedbackSize { get { throw null; } set { } }
        public override byte[] IV { get { throw null; } set { } }
        public override byte[] Key { get { throw null; } set { } }
        public override int KeySize { get { throw null; } set { } }
        public override System.Security.Cryptography.KeySizes[] LegalBlockSizes { get { throw null; } }
        public override System.Security.Cryptography.KeySizes[] LegalKeySizes { get { throw null; } }
        public override System.Security.Cryptography.CipherMode Mode { get { throw null; } set { } }
        public override System.Security.Cryptography.PaddingMode Padding { get { throw null; } set { } }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        protected override void Dispose(bool disposing) { }
        public override void GenerateIV() { }
        public override void GenerateKey() { }
    }
    public sealed partial class CspKeyContainerInfo
    {
        public CspKeyContainerInfo(System.Security.Cryptography.CspParameters parameters) { }
        public bool Accessible { get { throw null; } }
        public bool Exportable { get { throw null; } }
        public bool HardwareDevice { get { throw null; } }
        public string KeyContainerName { get { throw null; } }
        public System.Security.Cryptography.KeyNumber KeyNumber { get { throw null; } }
        public bool MachineKeyStore { get { throw null; } }
        public bool Protected { get { throw null; } }
        public string ProviderName { get { throw null; } }
        public int ProviderType { get { throw null; } }
        public bool RandomlyGenerated { get { throw null; } }
        public bool Removable { get { throw null; } }
        public string UniqueKeyContainerName { get { throw null; } }
    }
    public sealed partial class CspParameters
    {
        public string KeyContainerName;
        public int KeyNumber;
        public string ProviderName;
        public int ProviderType;
        public CspParameters() { }
        public CspParameters(int dwTypeIn) { }
        public CspParameters(int dwTypeIn, string strProviderNameIn) { }
        public CspParameters(int dwTypeIn, string strProviderNameIn, string strContainerNameIn) { }
        public System.Security.Cryptography.CspProviderFlags Flags { get { throw null; } set { } }
        [System.CLSCompliantAttribute(false)]
        public System.Security.SecureString KeyPassword { get { throw null; } set { } }
        public System.IntPtr ParentWindowHandle { get { throw null; } set { } }
    }
    [System.FlagsAttribute]
    public enum CspProviderFlags
    {
        NoFlags = 0,
        UseMachineKeyStore = 1,
        UseDefaultKeyContainer = 2,
        UseNonExportableKey = 4,
        UseExistingKey = 8,
        UseArchivableKey = 16,
        UseUserProtectedKey = 32,
        NoPrompt = 64,
        CreateEphemeralKey = 128,
    }
    public sealed partial class DESCryptoServiceProvider : System.Security.Cryptography.DES
    {
        public DESCryptoServiceProvider() { }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override void GenerateIV() { }
        public override void GenerateKey() { }
    }
    public sealed partial class DSACryptoServiceProvider : System.Security.Cryptography.DSA, System.Security.Cryptography.ICspAsymmetricAlgorithm
    {
        public DSACryptoServiceProvider() { }
        public DSACryptoServiceProvider(int dwKeySize) { }
        public DSACryptoServiceProvider(int dwKeySize, System.Security.Cryptography.CspParameters parameters) { }
        public DSACryptoServiceProvider(System.Security.Cryptography.CspParameters parameters) { }
        public System.Security.Cryptography.CspKeyContainerInfo CspKeyContainerInfo { get { throw null; } }
        public override string KeyExchangeAlgorithm { get { throw null; } }
        public override int KeySize { get { throw null; } }
        public override System.Security.Cryptography.KeySizes[] LegalKeySizes { get { throw null; } }
        public bool PersistKeyInCsp { get { throw null; } set { } }
        public bool PublicOnly { get { throw null; } }
        public override string SignatureAlgorithm { get { throw null; } }
        public static bool UseMachineKeyStore { get { throw null; } set { } }
        public override byte[] CreateSignature(byte[] rgbHash) { throw null; }
        protected override void Dispose(bool disposing) { }
        public byte[] ExportCspBlob(bool includePrivateParameters) { throw null; }
        public override System.Security.Cryptography.DSAParameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public void ImportCspBlob(byte[] keyBlob) { }
        public override void ImportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, System.ReadOnlySpan<byte> source, out int bytesRead) { throw null; }
        public override void ImportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<char> password, System.ReadOnlySpan<byte> source, out int bytesRead) { throw null; }
        public override void ImportParameters(System.Security.Cryptography.DSAParameters parameters) { }
        public byte[] SignData(byte[] buffer) { throw null; }
        public byte[] SignData(byte[] buffer, int offset, int count) { throw null; }
        public byte[] SignData(System.IO.Stream inputStream) { throw null; }
        public byte[] SignHash(byte[] rgbHash, string str) { throw null; }
        public bool VerifyData(byte[] rgbData, byte[] rgbSignature) { throw null; }
        public bool VerifyHash(byte[] rgbHash, string str, byte[] rgbSignature) { throw null; }
        public override bool VerifySignature(byte[] rgbHash, byte[] rgbSignature) { throw null; }
    }
    public sealed partial class Gost28147CryptoServiceProvider : System.Security.Cryptography.Gost28147
    {
        public Gost28147CryptoServiceProvider() { }
        public Gost28147CryptoServiceProvider(System.IntPtr keyHandle, System.IntPtr providerHandle) { }
        public Gost28147CryptoServiceProvider(System.Security.Cryptography.CspParameters parameters) { }
        public string CipherOid { get { throw null; } set { } }
        public override byte[] ComputeHash(System.Security.Cryptography.HashAlgorithm hash) { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override void GenerateIV() { }
        public override void GenerateKey() { }
        public override System.Security.Cryptography.SymmetricAlgorithm Unwrap(byte[] wrapped, System.Security.Cryptography.GostKeyWrapMethod method) { throw null; }
        public override byte[] Wrap(System.Security.Cryptography.Gost28147 prov, System.Security.Cryptography.GostKeyWrapMethod method) { throw null; }
    }
    public sealed partial class Gost3410CryptoServiceProvider : System.Security.Cryptography.Gost3410, System.Security.Cryptography.ICspAsymmetricAlgorithm
    {
        public Gost3410CryptoServiceProvider() { }
        public Gost3410CryptoServiceProvider(System.IntPtr hProvHandle, int keySpec) { }
        public Gost3410CryptoServiceProvider(System.Security.Cryptography.CspParameters parameters) { }
        public string CipherOid { get { throw null; } set { } }
        public DateTimeOffset NotAfter { get { throw null; } }
        public byte[] ContainerCertificate { get { throw null; } set { } }
        public System.Security.Cryptography.CspKeyContainerInfo CspKeyContainerInfo { get { throw null; } }
        public override int KeySize { get { throw null; } }
        public bool PersistKeyInCsp { get { throw null; } set { } }
        public bool PublicOnly { get { throw null; } }
        public static bool UseMachineKeyStore { get { throw null; } set { } }
        public override System.Security.Cryptography.GostSharedSecretAlgorithm CreateAgree(System.Security.Cryptography.Gost3410Parameters alg) { throw null; }
        protected override void Dispose(bool disposing) { }
        public byte[] ExportCspBlob(bool includePrivateParameters) { throw null; }
        public override System.Security.Cryptography.Gost3410Parameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public void ImportCspBlob(byte[] rawData) { }
        public void ImportCspBlob(byte[] keyBlob, byte[] paramBlob) { }
        public void ImportCertificatePublicKey(byte[] publicKeyInfo) { }
        public override void ImportParameters(System.Security.Cryptography.Gost3410Parameters parameters) { }
        public void PreloadContainer() { }
        public static string SelectContainer(bool fullyQualifiedContainerName, bool machine, System.IntPtr parent) { throw null; }
        public void SetContainerPassword(System.Security.SecureString password) { }
        public override byte[] SignData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override byte[] SignData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override byte[] SignHash(byte[] rgbHash) { throw null; }
        public override byte[] SignHash(byte[] rgbHash, System.Security.Cryptography.HashAlgorithmName hashAlgName) { throw null; }
        public override bool VerifyData(byte[] data, int offset, int count, byte[] rgbSignature, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public bool VerifyHash(byte[] rgbHash, byte[] rgbSignature) { throw null; }
        public override bool VerifyHash(byte[] hash, byte[] signature, System.Security.Cryptography.HashAlgorithmName hashAlgName) { throw null; }
    }
    public sealed partial class Gost3410EphemeralCryptoServiceProvider : System.Security.Cryptography.Gost3410
    {
        public Gost3410EphemeralCryptoServiceProvider() { }
        public Gost3410EphemeralCryptoServiceProvider(System.Security.Cryptography.Gost3410Parameters basedOn) { }
        public System.IntPtr KeyHandle { get { throw null; } }
        public System.IntPtr ProviderHandle { get { throw null; } }
        public override System.Security.Cryptography.GostSharedSecretAlgorithm CreateAgree(System.Security.Cryptography.Gost3410Parameters alg) { throw null; }
        protected override void Dispose(bool disposing) { }
        public override System.Security.Cryptography.Gost3410Parameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override void ImportParameters(System.Security.Cryptography.Gost3410Parameters parameters) { }
        public override byte[] SignHash(byte[] hash) { throw null; }
        public override byte[] SignHash(byte[] hash, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override bool VerifyHash(byte[] hash, byte[] signature, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
    }
    public sealed partial class Gost3410_2012_256CryptoServiceProvider : System.Security.Cryptography.Gost3410_2012_256, System.Security.Cryptography.ICspAsymmetricAlgorithm
    {
        public Gost3410_2012_256CryptoServiceProvider() { }
        public Gost3410_2012_256CryptoServiceProvider(System.IntPtr hProvHandle, int keySpec) { }
        public Gost3410_2012_256CryptoServiceProvider(System.Security.Cryptography.CspParameters parameters) { }
        public string CipherOid { get { throw null; } set { } }
        public DateTimeOffset NotAfter { get { throw null; } }
        public byte[] ContainerCertificate { get { throw null; } set { } }
        public System.Security.Cryptography.CspKeyContainerInfo CspKeyContainerInfo { get { throw null; } }
        public override int KeySize { get { throw null; } }
        public bool PersistKeyInCsp { get { throw null; } set { } }
        public bool PublicOnly { get { throw null; } }
        public static bool UseMachineKeyStore { get { throw null; } set { } }
        public override System.Security.Cryptography.GostSharedSecretAlgorithm CreateAgree(System.Security.Cryptography.Gost3410Parameters alg) { throw null; }
        protected override void Dispose(bool disposing) { }
        public byte[] ExportCspBlob(bool includePrivateParameters) { throw null; }
        public override System.Security.Cryptography.Gost3410Parameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public void ImportCspBlob(byte[] rawData) { }
        public void ImportCspBlob(byte[] keyBlob, byte[] paramBlob) { }
        public void ImportCertificatePublicKey(byte[] publicKeyInfo) { }
        public override void ImportParameters(System.Security.Cryptography.Gost3410Parameters parameters) { }
        public void PreloadContainer() { }
        public static string SelectContainer(bool fullyQualifiedContainerName, bool machine, System.IntPtr parent) { throw null; }
        public void SetContainerPassword(System.Security.SecureString password) { }
        public override byte[] SignData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override byte[] SignData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override byte[] SignHash(byte[] rgbHash) { throw null; }
        public override byte[] SignHash(byte[] rgbHash, System.Security.Cryptography.HashAlgorithmName hashAlgName) { throw null; }
        public override bool VerifyData(byte[] data, int offset, int count, byte[] rgbSignature, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public bool VerifyHash(byte[] rgbHash, byte[] rgbSignature) { throw null; }
        public override bool VerifyHash(byte[] hash, byte[] signature, System.Security.Cryptography.HashAlgorithmName hashAlgName) { throw null; }
    }
    public sealed partial class Gost3410_2012_256EphemeralCryptoServiceProvider : System.Security.Cryptography.Gost3410_2012_256
    {
        public Gost3410_2012_256EphemeralCryptoServiceProvider() { }
        public Gost3410_2012_256EphemeralCryptoServiceProvider(System.Security.Cryptography.Gost3410Parameters basedOn) { }
        public System.IntPtr KeyHandle { get { throw null; } }
        public System.IntPtr ProviderHandle { get { throw null; } }
        public override System.Security.Cryptography.GostSharedSecretAlgorithm CreateAgree(System.Security.Cryptography.Gost3410Parameters alg) { throw null; }
        protected override void Dispose(bool disposing) { }
        public override System.Security.Cryptography.Gost3410Parameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override void ImportParameters(System.Security.Cryptography.Gost3410Parameters parameters) { }
        public override byte[] SignHash(byte[] hash) { throw null; }
        public override byte[] SignHash(byte[] hash, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override bool VerifyHash(byte[] hash, byte[] signature, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
    }
    public sealed partial class Gost3410_2012_512CryptoServiceProvider : System.Security.Cryptography.Gost3410_2012_512, System.Security.Cryptography.ICspAsymmetricAlgorithm
    {
        public Gost3410_2012_512CryptoServiceProvider() { }
        public Gost3410_2012_512CryptoServiceProvider(System.IntPtr hProvHandle, int keySpec) { }
        public Gost3410_2012_512CryptoServiceProvider(System.Security.Cryptography.CspParameters parameters) { }
        public string CipherOid { get { throw null; } set { } }
        public DateTimeOffset NotAfter { get { throw null; } }
        public byte[] ContainerCertificate { get { throw null; } set { } }
        public System.Security.Cryptography.CspKeyContainerInfo CspKeyContainerInfo { get { throw null; } }
        public override int KeySize { get { throw null; } }
        public bool PersistKeyInCsp { get { throw null; } set { } }
        public bool PublicOnly { get { throw null; } }
        public static bool UseMachineKeyStore { get { throw null; } set { } }
        public override System.Security.Cryptography.GostSharedSecretAlgorithm CreateAgree(System.Security.Cryptography.Gost3410Parameters alg) { throw null; }
        protected override void Dispose(bool disposing) { }
        public byte[] ExportCspBlob(bool includePrivateParameters) { throw null; }
        public override System.Security.Cryptography.Gost3410Parameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public void ImportCspBlob(byte[] rawData) { }
        public void ImportCspBlob(byte[] keyBlob, byte[] paramBlob) { }
        public void ImportCertificatePublicKey(byte[] publicKeyInfo) { }
        public override void ImportParameters(System.Security.Cryptography.Gost3410Parameters parameters) { }
        public void PreloadContainer() { }
        public static string SelectContainer(bool fullyQualifiedContainerName, bool machine, System.IntPtr parent) { throw null; }
        public void SetContainerPassword(System.Security.SecureString password) { }
        public override byte[] SignData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override byte[] SignData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override byte[] SignHash(byte[] rgbHash) { throw null; }
        public override byte[] SignHash(byte[] rgbHash, System.Security.Cryptography.HashAlgorithmName hashAlgName) { throw null; }
        public override bool VerifyData(byte[] data, int offset, int count, byte[] rgbSignature, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public bool VerifyHash(byte[] rgbHash, byte[] rgbSignature) { throw null; }
        public override bool VerifyHash(byte[] hash, byte[] signature, System.Security.Cryptography.HashAlgorithmName hashAlgName) { throw null; }
    }
    public sealed partial class Gost3410_2012_512EphemeralCryptoServiceProvider : System.Security.Cryptography.Gost3410_2012_512
    {
        public Gost3410_2012_512EphemeralCryptoServiceProvider() { }
        public Gost3410_2012_512EphemeralCryptoServiceProvider(System.Security.Cryptography.Gost3410Parameters basedOn) { }
        public System.IntPtr KeyHandle { get { throw null; } }
        public System.IntPtr ProviderHandle { get { throw null; } }
        public override System.Security.Cryptography.GostSharedSecretAlgorithm CreateAgree(System.Security.Cryptography.Gost3410Parameters alg) { throw null; }
        protected override void Dispose(bool disposing) { }
        public override System.Security.Cryptography.Gost3410Parameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override void ImportParameters(System.Security.Cryptography.Gost3410Parameters parameters) { }
        public override byte[] SignHash(byte[] hash) { throw null; }
        public override byte[] SignHash(byte[] hash, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public override bool VerifyHash(byte[] hash, byte[] signature, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
    }
    public sealed partial class Gost3411CryptoServiceProvider : System.Security.Cryptography.Gost3411
    {
        public Gost3411CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public sealed partial class Gost3411_2012_256CryptoServiceProvider : System.Security.Cryptography.Gost3411_2012_256
    {
        public Gost3411_2012_256CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public sealed partial class Gost3411_2012_512CryptoServiceProvider : System.Security.Cryptography.Gost3411_2012_512
    {
        public Gost3411_2012_512CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public partial class GostKeyExchangeDeformatter : System.Security.Cryptography.AsymmetricKeyExchangeDeformatter
    {
        public GostKeyExchangeDeformatter() { }
        public GostKeyExchangeDeformatter(System.Security.Cryptography.AsymmetricAlgorithm key) { }
        public override string Parameters { get { throw null; } set { } }
        public override byte[] DecryptKeyExchange(byte[] rgb) { throw null; }
        public System.Security.Cryptography.SymmetricAlgorithm DecryptKeyExchange(System.Security.Cryptography.GostKeyTransport transport, System.Security.Cryptography.GostKeyWrapMethod keyWrapMethod = System.Security.Cryptography.GostKeyWrapMethod.CryptoPro12KeyWrap) { throw null; }
        public System.Security.Cryptography.SymmetricAlgorithm DecryptKeyExchangeData(byte[] data) { throw null; }
        public override void SetKey(System.Security.Cryptography.AsymmetricAlgorithm key) { }
    }
    public partial class GostKeyExchangeFormatter : System.Security.Cryptography.AsymmetricKeyExchangeFormatter
    {
        public GostKeyExchangeFormatter() { }
        public GostKeyExchangeFormatter(System.Security.Cryptography.AsymmetricAlgorithm key) { }
        public override string Parameters { get { throw null; } }
        public override byte[] CreateKeyExchange(byte[] data) { throw null; }
        public override byte[] CreateKeyExchange(byte[] data, System.Type symAlgType) { throw null; }
        public System.Security.Cryptography.GostKeyTransport CreateKeyExchange(System.Security.Cryptography.SymmetricAlgorithm alg, System.Security.Cryptography.GostKeyWrapMethod keyWrapMethod = System.Security.Cryptography.GostKeyWrapMethod.CryptoPro12KeyWrap) { throw null; }
        public byte[] CreateKeyExchangeData(System.Security.Cryptography.SymmetricAlgorithm alg, System.Security.Cryptography.GostKeyWrapMethod wrapMethod = System.Security.Cryptography.GostKeyWrapMethod.CryptoPro12KeyWrap) { throw null; }
        public override void SetKey(System.Security.Cryptography.AsymmetricAlgorithm key) { }
    }
    public sealed partial class GostKeyExchangeParameters
    {
        public string DigestParamSet;
        public string EncryptionParamSet;
        public byte[] PrivateKey;
        public byte[] PublicKey;
        public string PublicKeyParamSet;
        public GostKeyExchangeParameters() { }
        public GostKeyExchangeParameters(System.Security.Cryptography.GostKeyExchangeParameters parameters) { }
        public void DecodeParameters(byte[] data) { }
        public void DecodePublicKey(byte[] data, int algId) { }
        public byte[] EncodeParameters() { throw null; }
        public static byte[] EncodePublicBlob(System.Security.Cryptography.GostKeyExchangeParameters publicKeyParameters, int algId) { throw null; }
    }
    public partial struct GostKeyTransport
    {
        public System.Security.Cryptography.GostWrappedKey SessionEncryptedKey;
        public System.Security.Cryptography.Gost3410Parameters TransportParameters;
        public void Decode(byte[] data) { }
        public byte[] Encode() { throw null; }
    }
    public sealed partial class GostSharedSecretCryptoServiceProvider : System.Security.Cryptography.GostSharedSecretAlgorithm
    {
        internal GostSharedSecretCryptoServiceProvider() { }
        public System.IntPtr KeyHandle { get { throw null; } }
        public System.IntPtr ProviderHandle { get { throw null; } }
        protected override void Dispose(bool disposing) { }
        public override System.Security.Cryptography.SymmetricAlgorithm Unwrap(byte[] wrapped, System.Security.Cryptography.GostKeyWrapMethod method) { throw null; }
        public override byte[] Wrap(System.Security.Cryptography.SymmetricAlgorithm alg, System.Security.Cryptography.GostKeyWrapMethod method) { throw null; }
    }
    public partial struct GostWrappedKey
    {
        public byte[] EncryptedKey;
        public string EncryptionParamSet;
        public byte[] Mac;
        public byte[] Ukm;
        public byte[] GetCryptoServiceProviderBlob() { throw null; }
        public byte[] GetXmlWrappedKey() { throw null; }
        public void SetByCryptoServiceProviderBlob(byte[] data) { }
        public void SetByXmlWrappedKey(byte[] data) { }
    }
    public partial interface ICspAsymmetricAlgorithm
    {
        System.Security.Cryptography.CspKeyContainerInfo CspKeyContainerInfo { get; }
        byte[] ExportCspBlob(bool includePrivateParameters);
        void ImportCspBlob(byte[] rawData);
    }
    public enum KeyNumber
    {
        Exchange = 1,
        Signature = 2,
    }
    public sealed partial class MD5CryptoServiceProvider : System.Security.Cryptography.MD5
    {
        public MD5CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public partial class PasswordDeriveBytes : System.Security.Cryptography.DeriveBytes
    {
        public PasswordDeriveBytes(byte[] password, byte[] salt) { }
        public PasswordDeriveBytes(byte[] password, byte[] salt, System.Security.Cryptography.CspParameters cspParams) { }
        public PasswordDeriveBytes(byte[] password, byte[] salt, string hashName, int iterations) { }
        public PasswordDeriveBytes(byte[] password, byte[] salt, string hashName, int iterations, System.Security.Cryptography.CspParameters cspParams) { }
        public PasswordDeriveBytes(string strPassword, byte[] rgbSalt) { }
        public PasswordDeriveBytes(string strPassword, byte[] rgbSalt, System.Security.Cryptography.CspParameters cspParams) { }
        public PasswordDeriveBytes(string strPassword, byte[] rgbSalt, string strHashName, int iterations) { }
        public PasswordDeriveBytes(string strPassword, byte[] rgbSalt, string strHashName, int iterations, System.Security.Cryptography.CspParameters cspParams) { }
        public string HashName { get { throw null; } set { } }
        public int IterationCount { get { throw null; } set { } }
        public byte[] Salt { get { throw null; } set { } }
        public byte[] CryptDeriveKey(string algname, string alghashname, int keySize, byte[] rgbIV) { throw null; }
        protected override void Dispose(bool disposing) { }
        public override byte[] GetBytes(int cb) { throw null; }
        public override void Reset() { }
    }
    public sealed partial class RC2CryptoServiceProvider : System.Security.Cryptography.RC2
    {
        public RC2CryptoServiceProvider() { }
        public override int EffectiveKeySize { get { throw null; } set { } }
        public bool UseSalt { get { throw null; } set { } }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override void GenerateIV() { }
        public override void GenerateKey() { }
    }
    public sealed partial class RNGCryptoServiceProvider : System.Security.Cryptography.RandomNumberGenerator
    {
        public RNGCryptoServiceProvider() { }
        public RNGCryptoServiceProvider(byte[] rgb) { }
        public RNGCryptoServiceProvider(System.Security.Cryptography.CspParameters cspParams) { }
        public RNGCryptoServiceProvider(string str) { }
        protected override void Dispose(bool disposing) { }
        public override void GetBytes(byte[] data) { }
        public override void GetBytes(byte[] data, int offset, int count) { }
        public override void GetBytes(System.Span<byte> data) { }
        public override void GetNonZeroBytes(byte[] data) { }
        public override void GetNonZeroBytes(System.Span<byte> data) { }
    }
    public sealed partial class RSACryptoServiceProvider : System.Security.Cryptography.RSA, System.Security.Cryptography.ICspAsymmetricAlgorithm
    {
        public RSACryptoServiceProvider() { }
        public RSACryptoServiceProvider(int dwKeySize) { }
        public RSACryptoServiceProvider(int dwKeySize, System.Security.Cryptography.CspParameters parameters) { }
        public RSACryptoServiceProvider(System.Security.Cryptography.CspParameters parameters) { }
        public System.Security.Cryptography.CspKeyContainerInfo CspKeyContainerInfo { get { throw null; } }
        public override string KeyExchangeAlgorithm { get { throw null; } }
        public override int KeySize { get { throw null; } }
        public override System.Security.Cryptography.KeySizes[] LegalKeySizes { get { throw null; } }
        public bool PersistKeyInCsp { get { throw null; } set { } }
        public bool PublicOnly { get { throw null; } }
        public override string SignatureAlgorithm { get { throw null; } }
        public static bool UseMachineKeyStore { get { throw null; } set { } }
        public byte[] Decrypt(byte[] rgb, bool fOAEP) { throw null; }
        public override byte[] Decrypt(byte[] data, System.Security.Cryptography.RSAEncryptionPadding padding) { throw null; }
        public override byte[] DecryptValue(byte[] rgb) { throw null; }
        protected override void Dispose(bool disposing) { }
        public byte[] Encrypt(byte[] rgb, bool fOAEP) { throw null; }
        public override byte[] Encrypt(byte[] data, System.Security.Cryptography.RSAEncryptionPadding padding) { throw null; }
        public override byte[] EncryptValue(byte[] rgb) { throw null; }
        public byte[] ExportCspBlob(bool includePrivateParameters) { throw null; }
        public override System.Security.Cryptography.RSAParameters ExportParameters(bool includePrivateParameters) { throw null; }
        protected override byte[] HashData(byte[] data, int offset, int count, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        protected override byte[] HashData(System.IO.Stream data, System.Security.Cryptography.HashAlgorithmName hashAlgorithm) { throw null; }
        public void ImportCspBlob(byte[] keyBlob) { }
        public override void ImportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<byte> passwordBytes, System.ReadOnlySpan<byte> source, out int bytesRead) { throw null; }
        public override void ImportEncryptedPkcs8PrivateKey(System.ReadOnlySpan<char> password, System.ReadOnlySpan<byte> source, out int bytesRead) { throw null; }
        public override void ImportParameters(System.Security.Cryptography.RSAParameters parameters) { }
        public byte[] SignData(byte[] buffer, int offset, int count, object halg) { throw null; }
        public byte[] SignData(byte[] buffer, object halg) { throw null; }
        public byte[] SignData(System.IO.Stream inputStream, object halg) { throw null; }
        public override byte[] SignHash(byte[] hash, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, System.Security.Cryptography.RSASignaturePadding padding) { throw null; }
        public byte[] SignHash(byte[] rgbHash, string str) { throw null; }
        public bool VerifyData(byte[] buffer, object halg, byte[] signature) { throw null; }
        public override bool VerifyHash(byte[] hash, byte[] signature, System.Security.Cryptography.HashAlgorithmName hashAlgorithm, System.Security.Cryptography.RSASignaturePadding padding) { throw null; }
        public bool VerifyHash(byte[] rgbHash, string str, byte[] rgbSignature) { throw null; }
    }
    public sealed partial class SHA1CryptoServiceProvider : System.Security.Cryptography.SHA1
    {
        public SHA1CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public sealed partial class SHA256CryptoServiceProvider : System.Security.Cryptography.SHA256
    {
        public SHA256CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public sealed partial class SHA384CryptoServiceProvider : System.Security.Cryptography.SHA384
    {
        public SHA384CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public sealed partial class SHA512CryptoServiceProvider : System.Security.Cryptography.SHA512
    {
        public SHA512CryptoServiceProvider() { }
        protected override void Dispose(bool disposing) { }
        protected override void HashCore(byte[] array, int ibStart, int cbSize) { }
        protected override void HashCore(System.ReadOnlySpan<byte> source) { }
        protected override byte[] HashFinal() { throw null; }
        public override void Initialize() { }
        protected override bool TryHashFinal(System.Span<byte> destination, out int bytesWritten) { throw null; }
    }
    public sealed partial class TripleDESCryptoServiceProvider : System.Security.Cryptography.TripleDES
    {
        public TripleDESCryptoServiceProvider() { }
        public override int BlockSize { get { throw null; } set { } }
        public override int FeedbackSize { get { throw null; } set { } }
        public override byte[] IV { get { throw null; } set { } }
        public override byte[] Key { get { throw null; } set { } }
        public override int KeySize { get { throw null; } set { } }
        public override System.Security.Cryptography.KeySizes[] LegalBlockSizes { get { throw null; } }
        public override System.Security.Cryptography.KeySizes[] LegalKeySizes { get { throw null; } }
        public override System.Security.Cryptography.CipherMode Mode { get { throw null; } set { } }
        public override System.Security.Cryptography.PaddingMode Padding { get { throw null; } set { } }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateDecryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor() { throw null; }
        public override System.Security.Cryptography.ICryptoTransform CreateEncryptor(byte[] rgbKey, byte[] rgbIV) { throw null; }
        protected override void Dispose(bool disposing) { }
        public override void GenerateIV() { }
        public override void GenerateKey() { }
    }
}
