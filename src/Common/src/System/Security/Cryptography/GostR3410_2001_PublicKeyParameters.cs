// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.Security.Cryptography
{
	class GostR3410_2001_PublicKeyParameters : Asn1Type
	{
		public Asn1ObjectIdentifier DigestParamSet;
		public Asn1ObjectIdentifier PublicKeyParamSet;
		public Gost28147_89_ParamSet EncryptionParamSet;

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			var elemLength = explicitTagging ? MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

			Init();

			var context = new Asn1BerDecodeContext(buffer, elemLength);
			var parsedLen = new IntHolder();

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
                throw new Exception("Asn1MissingRequiredException");
			}

			PublicKeyParamSet = new Asn1ObjectIdentifier();
			PublicKeyParamSet.Decode(buffer, true, parsedLen.Value);

			if (!context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
                throw new Exception("Asn1MissingRequiredException");
			}

			DigestParamSet = new Asn1ObjectIdentifier();
			DigestParamSet.Decode(buffer, true, parsedLen.Value);

			if (context.MatchElemTag(0, 0, ObjectIdentifierTypeCode, parsedLen, false))
			{
				EncryptionParamSet = new Gost28147_89_ParamSet();
				EncryptionParamSet.Decode(buffer, true, parsedLen.Value);
			}
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			var len = 0;

			if (EncryptionParamSet != null)
			{
				len += EncryptionParamSet.Encode(buffer, true);
			}

			len += DigestParamSet.Encode(buffer, true);
			len += PublicKeyParamSet.Encode(buffer, true);

			if (explicitTagging)
			{
				len += buffer.EncodeTagAndLength(Asn1Tag.Sequence, len);
			}

			return len;
		}

		private void Init()
		{
			DigestParamSet = null;
			PublicKeyParamSet = null;
			EncryptionParamSet = null;
		}
	}
}
