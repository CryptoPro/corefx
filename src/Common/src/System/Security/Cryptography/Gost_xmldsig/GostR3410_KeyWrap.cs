namespace System.Security.Cryptography
{
    class GostR3410_KeyWrap : Asn1Type
    {
        public Gost28147_89_EncryptedKey encryptedKey;
        public Gost28147_89_KeyWrapParameters encryptedParameters;

        public GostR3410_KeyWrap() : base()
        {
        }

        /// <summary>
        /// This constructor sets all elements to references to the 
        /// given objects
        /// </summary>
        public GostR3410_KeyWrap(
           Gost28147_89_EncryptedKey encryptedKey_,
           Gost28147_89_KeyWrapParameters encryptedParameters_
        )
           : base()
        {
            encryptedKey = encryptedKey_;
            encryptedParameters = encryptedParameters_;
        }

        public void Init()
        {
            encryptedKey = null;
            encryptedParameters = null;
        }

        public override void Decode
           (Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
        {
            int llen = (explicitTagging) ?
               MatchTag(buffer, Asn1Tag.Sequence) : implicitLength;

            Init();

            // decode SEQUENCE

            Asn1BerDecodeContext context =
               new Asn1BerDecodeContext(buffer, llen);

            IntHolder elemLen = new IntHolder();

            // decode encryptedKey

            if (context.MatchElemTag(Asn1Tag.Universal, Asn1Tag.CONS, 16, elemLen, false))
            {
                encryptedKey = new Gost28147_89_EncryptedKey();
                encryptedKey.Decode(buffer, true, elemLen.Value);
            }
            else
                throw new Exception("Asn1MissingRequiredException");

            // decode encryptedParameters

            if (context.MatchElemTag(Asn1Tag.Universal, Asn1Tag.CONS, 16, elemLen, false))
            {
                encryptedParameters = new Gost28147_89_KeyWrapParameters();
                encryptedParameters.Decode(buffer, true, elemLen.Value);
            }
            else
                throw new Exception("Asn1MissingRequiredException");

        }

        public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
        {
            int _aal = 0, len;

            // encode encryptedParameters

            len = encryptedParameters.Encode(buffer, true);
            _aal += len;

            // encode encryptedKey

            len = encryptedKey.Encode(buffer, true);
            _aal += len;

            if (explicitTagging)
            {
                _aal += buffer.EncodeTagAndLength(Asn1Tag.Sequence, _aal);
            }

            return (_aal);
        }
    }
}
