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
            // Исходное сообщение.
            const String msg = "Это сообщение, которое будет зашифровано.";

            Console.WriteLine("{0}Исходное сообщение (длина {1}): {2}  ",
                Environment.NewLine, msg.Length, msg);

            // Переводим исходное сообщение в массив байтов.
            UnicodeEncoding unicode = new UnicodeEncoding();
            byte[] msgBytes = unicode.GetBytes(msg);

            Console.WriteLine("{0}{0}------------------------------",
                Environment.NewLine);
            Console.WriteLine(" Поиск сертификатов           ");
            Console.WriteLine("------------------------------{0}",
                Environment.NewLine);

            // Сертификаты получателей необходимы для
            // зашифрования сообщения.
            var cert = GetGost2012_256Certificate();

            //X509Certificate2Collection recipientCerts =
            //    new X509Certificate2Collection(cert);

            Console.WriteLine("{0}{0}------------------------------",
                Environment.NewLine);
            Console.WriteLine(" На стороне отправителя");
            Console.WriteLine("------------------------------{0}",
                Environment.NewLine);

            byte[] encodedEnvelopedCms = EncryptMsg(msgBytes,
                cert, true);
            File.WriteAllBytes("encrypted2.bin", encodedEnvelopedCms);

            Console.WriteLine("{0}Сообщение после зашифрования (длина {1}):  ",
                Environment.NewLine, encodedEnvelopedCms.Length);
            foreach (byte b in encodedEnvelopedCms)
            {
                Console.Write("{0:x}", b);
            }
            Console.WriteLine();

            Console.WriteLine("{0}{0}------------------------------",
                Environment.NewLine);
            Console.WriteLine(" На стороне получателя  ");
            Console.WriteLine("------------------------------{0}",
                Environment.NewLine);

            // Расшифровываем сообщение для одного из получателей
            // и возвращаем сообщение для отображения.
            Byte[] decryptedMsg = DecryptMsg(encodedEnvelopedCms, cert);

            // Преобразуем расшифрованные байты в сообщение
            Console.WriteLine("{0}Расшифрованное сообщение: {1}",
                Environment.NewLine, unicode.GetString(decryptedMsg));
        }

        // Зашифровываем сообщение, используя открытый ключ 
        // получателя, при помощи класса EnvelopedCms.
        static byte[] EncryptMsg(
            Byte[] msg,
            X509Certificate2 recipientCert,
            bool useDataContextType)
        {
            // Помещаем сообщение в объект ContentInfo 
            // Это требуется для создания объекта EnvelopedCms.

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

            // Создаем объект EnvelopedCms, передавая ему
            // только что созданный объект ContentInfo.
            // Используем идентификацию получателя (SubjectIdentifierType)
            // по умолчанию (IssuerAndSerialNumber).
            // Не устанавливаем алгоритм зашифрования тела сообщения:
            // ContentEncryptionAlgorithm устанавливается в 
            // RSA_DES_EDE3_CBC, несмотря на это, при зашифровании
            // сообщения в адрес получателя с ГОСТ сертификатом,
            // будет использован алгоритм GOST 28147-89.
            //EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo, new AlgorithmIdentifier(new Oid("1.2.840.113549.3.7")));
            EnvelopedCms envelopedCms = new EnvelopedCms(contentInfo);

            // Создаем объект CmsRecipient, который 
            // идентифицирует получателя зашифрованного сообщения.
            CmsRecipient recip1 = new CmsRecipient(
                SubjectIdentifierType.IssuerAndSerialNumber,
                recipientCert);

            Console.Write(
                "Зашифровываем данные для одного получателя " +
                "с именем {0} ...",
                recip1.Certificate.SubjectName.Name);
            // Зашифровываем сообщение.
            envelopedCms.Encrypt(recip1);
            Console.WriteLine("Выполнено.");

            // Закодированное EnvelopedCms сообщение содержит
            // зашифрованный текст сообщения и информацию
            // о каждом получателе данного сообщения.
            return envelopedCms.Encode();
        }

        // Расшифрование закодированного EnvelopedCms сообщения.
        static Byte[] DecryptMsg(byte[] encodedEnvelopedCms, X509Certificate2 cert)
        {
            // Создаем объект для декодирования и расшифрования.
            EnvelopedCms envelopedCms = new EnvelopedCms();

            // Декодируем сообщение.
            envelopedCms.Decode(encodedEnvelopedCms);

            // Выводим количество получателей сообщения
            // (в данном примере должно быть равно 1) и
            // алгоритм зашифрования.
            DisplayEnvelopedCms(envelopedCms, false);

            // Расшифровываем сообщение для единственного 
            // получателя.
            Console.Write("Расшифрование ... ");
            envelopedCms.Decrypt(new X509Certificate2Collection(cert));
            Console.WriteLine("Выполнено.");

            // После вызова метода Decrypt в свойстве ContentInfo 
            // содержится расшифрованное сообщение.
            return envelopedCms.ContentInfo.Content;
        }

        // Отображаем свойство ContentInfo объекта EnvelopedCms 
        static private void DisplayEnvelopedCmsContent(String desc,
            EnvelopedCms envelopedCms)
        {
            Console.WriteLine(desc + " (длина {0}):  ",
                envelopedCms.ContentInfo.Content.Length);
            foreach (byte b in envelopedCms.ContentInfo.Content)
            {
                Console.Write(b.ToString() + " ");
            }
            Console.WriteLine();
        }

        // Отображаем некоторые свойства объекта EnvelopedCms.
        static private void DisplayEnvelopedCms(EnvelopedCms e,
            Boolean displayContent)
        {
            Console.WriteLine("{0}Закодированное CMS/PKCS #7 Сообщение.{0}" +
                "Информация:", Environment.NewLine);
            Console.WriteLine("\tАлгоритм шифрования сообщения:{0}",
                e.ContentEncryptionAlgorithm.Oid.FriendlyName);
            Console.WriteLine(
                "\tКоличество получателей закодированного CMS/PKCS #7 сообщения:{0}",
                e.RecipientInfos.Count);
            for (int i = 0; i < e.RecipientInfos.Count; i++)
            {
                Console.WriteLine(
                    "\tПолучатель #{0} тип {1}.",
                    i + 1,
                    e.RecipientInfos[i].RecipientIdentifier.Type);
            }
            if (displayContent)
            {
                DisplayEnvelopedCmsContent("Закодированное CMS/PKCS " +
                    "#7 содержимое", e);
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

