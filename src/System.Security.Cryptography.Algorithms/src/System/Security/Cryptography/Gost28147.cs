// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.ComponentModel;

namespace System.Security.Cryptography
{
    using Internal.Cryptography;

    [EditorBrowsable(EditorBrowsableState.Never)]
    public abstract class Gost28147 : SymmetricAlgorithm
    {
        protected Gost28147()
        {
            KeySizeValue = DefaultKeySize;
            BlockSizeValue = DefaultBlockSize;
            FeedbackSizeValue = DefaultFeedbackSize;
            LegalBlockSizesValue = DefaultLegalBlockSizes;
            LegalKeySizesValue = DefaultLegalKeySizes;
        }

        /// <summary>
        /// ������ ����� 256 ���.
        /// </summary>
        public const int DefaultBlockSize = 64;
        /// <summary>
        /// ������ ����� 64 ����.
        /// </summary>
        public const int DefaultKeySize = 256;
        /// <summary>
        /// ������ ���������� 64 ����.
        /// </summary>
        public const int DefaultFeedbackSize = 64;
        /// <summary>
        /// ������ ������������� 64 ����.
        /// </summary>
        public const int DefaultIvSize = 64;

        public static readonly KeySizes[] DefaultLegalKeySizes = { new KeySizes(DefaultKeySize, DefaultKeySize, 0) };
        public static readonly KeySizes[] DefaultLegalBlockSizes = { new KeySizes(DefaultBlockSize, DefaultBlockSize, 0) };


        /// <summary>
        /// �������� �������, ������������ �������� ���������� ����-28147.
        /// </summary>
        /// 
        /// <returns>����������������� ������, ����������� �������� ���� 
        /// 28147.</returns>
        /// 
        /// <remarks><para>�������� ������� ��������� ���������� ���� 28147. 
        /// ������ ����� ��������������
        /// ��� ������������� ������������ � �������������.</para></remarks>
        /// 
        ///// <doc-sample path="Simple\Encrypt" name="EncryptDecryptRandomFile"
        ///// region="EncryptDecryptRandomFile">������ ������������ �
        ///// ������������� ����� ��� ������ 
        /////  ������������ ������ <see cref="Gost28147CryptoServiceProvider"/>.
        /////  </doc-sample>
        public new static Gost28147 Create()
        {
            // �������� ������� ���� �� ������������ ��� ��������� ��������� 
            // ������ ������ ������ Gost28147.
            return (Gost28147)CryptoConfig.CreateFromName(typeof(Gost28147).Name);
        }

        /// <summary>
        /// �������� �������, ������������ �������� ���������� ����-28147 
        /// � �������� ������ ����������.
        /// </summary>
        /// 
        /// <param name="algName">��� ���������� ���������.</param>
        /// 
        /// <returns>����������������� ������, ����������� �������� 
        /// ���� 28147.</returns>
        /// 
        ///// <doc-sample path="Simple\Encrypt" name="EncryptDecryptRandomFile"
        ///// region="EncryptDecryptRandomFile">������ ������������ �
        ///// ������������� ����� ��� ������ 
        /////  ������������ ������ <see cref="Gost28147CryptoServiceProvider"/>.
        /////  </doc-sample>
        public new static Gost28147 Create(string algName)
        {
            // �������� ������� ���� �� ������������ ��� ��������� ��������� 
            // ����������.
            return (Gost28147)CryptoConfig.CreateFromName(algName);
        }

        /// <summary>
        /// �������� ��������� ����.
        /// </summary>
        /// 
        /// <param name="hash">�����, ����������� ������� �����������.</param>
        /// 
        /// <returns>���-�������� ���������� �����</returns>
        public abstract byte[] ComputeHash(HashAlgorithm hash);

        /// <summary>
        /// ������������ (�������) ��������� ����.
        /// </summary>
        /// <param name="prov">��������� ����.</param>
        /// <param name="method">�������� �������� �����.</param>
        /// <returns>������������� ������������ ����</returns>
        public abstract byte[] Wrap(Gost28147 prov, GostKeyWrapMethod method);

        /// <summary>
        /// ����������� (���������) ��������� ����.
        /// </summary>
        /// <param name="wrapped">������������� ��������� ����.</param>
        /// <param name="method">�������� �������� �����.</param>
        public abstract SymmetricAlgorithm Unwrap(byte[] wrapped, GostKeyWrapMethod method);
    }
}
