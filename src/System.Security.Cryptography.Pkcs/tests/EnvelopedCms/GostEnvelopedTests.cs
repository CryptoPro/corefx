// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.IO;
using System.Linq;
using System.Globalization;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Runtime.InteropServices;
using System.Text;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.Xml;
using System.Security.Cryptography.X509Certificates;
using Xunit;

using Test.Cryptography;
using System.Security.Cryptography.Pkcs.Tests;

namespace System.Security.Cryptography.Pkcs.EnvelopedCmsTests.Tests
{
    public static partial class GostEnvelopedTests
    {
        [Fact]
        public static void EnvelopedCmsGost()
        {
            // �������� ���������.
            const String msg = "��� ���������, ������� ����� �����������.";

            Console.WriteLine("{0}�������� ��������� (����� {1}): {2}  ",
                Environment.NewLine, msg.Length, msg);

            // ��������� �������� ��������� � ������ ������.
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] msgBytes = unicode.GetBytes(msg);

            Console.WriteLine("{0}{0}------------------------------",
                Environment.NewLine);
            Console.WriteLine(" ����� ������������           ");
            Console.WriteLine("------------------------------{0}",
                Environment.NewLine);

            // ����������� ����������� ���������� ���
            // ������������ ���������.
            var cert = GetGost2012_256Certificate();

            //X509Certificate2Collection recipientCerts =
            //    new X509Certificate2Collection(cert);

            Console.WriteLine("{0}{0}------------------------------",
                Environment.NewLine);
            Console.WriteLine(" �� ������� �����������");
            Console.WriteLine("------------------------------{0}",
                Environment.NewLine);

            byte[] encodedEnvelopedCms = EncryptMsg(msgBytes,
                cert, true);
            File.WriteAllBytes("encrypted2.bin", encodedEnvelopedCms);

            Console.WriteLine("{0}��������� ����� ������������ (����� {1}):  ",
                Environment.NewLine, encodedEnvelopedCms.Length);
            foreach (byte b in encodedEnvelopedCms)
            {
                Console.Write("{0:x}", b);
            }
            Console.WriteLine();

            Console.WriteLine("{0}{0}------------------------------",
                Environment.NewLine);
            Console.WriteLine(" �� ������� ����������  ");
            Console.WriteLine("------------------------------{0}",
                Environment.NewLine);

            // �������������� ��������� ��� ������ �� �����������
            // � ���������� ��������� ��� �����������.
            Byte[] decryptedMsg = DecryptMsg(encodedEnvelopedCms, cert);

            // ����������� �������������� ����� � ���������
            Console.WriteLine("{0}�������������� ���������: {1}",
                Environment.NewLine, unicode.GetString(decryptedMsg));
        }

        // ������������� ���������, ��������� �������� ���� 
        // ����������, ��� ������ ������ EnvelopedCms.
        static byte[] EncryptMsg(
            Byte[] msg,
            X509Certificate2 recipientCert,
            bool useDataContextType)
        {
            // �������� ��������� � ������ ContentInfo 
            // ��� ��������� ��� �������� ������� EnvelopedCms.

            ContentInfo contentInfo;
            if (useDataContextType)
            {
                contentInfo = new ContentInfo(
                    new Oid("1.2.840.113549.1.7.1"),
                    msg);
            }
            else
            {
                contentInfo = new ContentInfo(
                    ContentInfo.GetContentType(msg),
                    msg);
            }
            //contentInfo = new ContentInfo(msg);

            // ������� ������ EnvelopedCms, ��������� ���
            // ������ ��� ��������� ������ ContentInfo.
            // ���������� ������������� ���������� (SubjectIdentifierType)
            // �� ��������� (IssuerAndSerialNumber).
            // �� ������������� �������� ������������ ���� ���������:
            // ContentEncryptionAlgorithm ��������������� � 
            // RSA_DES_EDE3_CBC, �������� �� ���, ��� ������������
            // ��������� � ����� ���������� � ���� ������������,
            // ����� ����������� �������� GOST 28147-89.
            //EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo, new AlgorithmIdentifier(new Oid("1.2.840.113549.3.7")));
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);

            // ������� ������ CmsRecipient, ������� 
            // �������������� ���������� �������������� ���������.
            CmsRecipient recip1 = new CmsRecipient(
                SubjectIdentifierType.IssuerAndSerialNumber,
                recipientCert);

            Console.Write(
                "������������� ������ ��� ������ ���������� " +
                "� ������ {0} ...",
                recip1.Certificate.SubjectName.Name);
            // ������������� ���������.
            envelopedCms.Encrypt(recip1);
            Console.WriteLine("���������.");

            // �������������� EnvelopedCms ��������� ��������
            // ������������� ����� ��������� � ����������
            // � ������ ���������� ������� ���������.
            return envelopedCms.Encode();
        }

        // ������������� ��������������� EnvelopedCms ���������.
        static Byte[] DecryptMsg(byte[] encodedEnvelopedCms, X509Certificate2 cert)
        {
            // ������� ������ ��� ������������� � �������������.
            EnvelopedCms envelopedCms = new EnvelopedCms();

            // ���������� ���������.
            envelopedCms.Decode(encodedEnvelopedCms);

            // ������� ���������� ����������� ���������
            // (� ������ ������� ������ ���� ����� 1) �
            // �������� ������������.
            DisplayEnvelopedCms(envelopedCms, false);

            // �������������� ��������� ��� ������������� 
            // ����������.
            Console.Write("������������� ... ");
            envelopedCms.Decrypt(new X509Certificate2Collection(cert));
            Console.WriteLine("���������.");

            // ����� ������ ������ Decrypt � �������� ContentInfo 
            // ���������� �������������� ���������.
            return envelopedCms.ContentInfo.Content;
        }

        // ���������� �������� ContentInfo ������� EnvelopedCms 
        static private void DisplayEnvelopedCmsContent(String desc,
            EnvelopedCms envelopedCms)
        {
            Console.WriteLine(desc + " (����� {0}):  ",
                envelopedCms.ContentInfo.Content.Length);
            foreach (byte b in envelopedCms.ContentInfo.Content)
            {
                Console.Write(b.ToString() + " ");
            }
            Console.WriteLine();
        }

        // ���������� ��������� �������� ������� EnvelopedCms.
        static private void DisplayEnvelopedCms(EnvelopedCms e,
            Boolean displayContent)
        {
            Console.WriteLine("{0}�������������� CMS/PKCS #7 ���������.{0}" +
                "����������:", Environment.NewLine);
            Console.WriteLine("\t�������� ���������� ���������:{0}",
                e.ContentEncryptionAlgorithm.Oid.FriendlyName);
            Console.WriteLine(
                "\t���������� ����������� ��������������� CMS/PKCS #7 ���������:{0}",
                e.RecipientInfos.Count);
            for (int i = 0; i < e.RecipientInfos.Count; i++)
            {
                Console.WriteLine(
                    "\t���������� #{0} ��� {1}.",
                    i + 1,
                    e.RecipientInfos[i].RecipientIdentifier.Type);
            }
            if (displayContent)
            {
                DisplayEnvelopedCmsContent("�������������� CMS/PKCS " +
                    "#7 ����������", e);
            }
            Console.WriteLine();
        }

        private static X509Certificate2 GetGost2012_256Certificate()
        {
            using (var store = new X509Store(StoreName.My, StoreLocation.CurrentUser))
            {
                store.Open(OpenFlags.ReadOnly);
                return store.Certificates.Find(X509FindType.FindBySubjectName, "G2012256", false)[0];
            }
        }
    }
}

