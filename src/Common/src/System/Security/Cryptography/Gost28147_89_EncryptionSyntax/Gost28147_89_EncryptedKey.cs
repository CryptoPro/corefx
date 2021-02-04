namespace System.Security.Cryptography
{

    class Gost28147_89_EncryptedKey : Asn1Type
    {
        public Gost28147_89_Key encryptedKey;
        public Gost28147_89_Key maskKey;  // optional
        public Gost28147_89_MAC macKey;

        public Gost28147_89_EncryptedKey() : base()
        {
        }

        /// <summary>
        /// This constructor sets all elements to references to the 
        /// given objects
        /// </summary>
        public Gost28147_89_EncryptedKey(
           Gost28147_89_Key encryptedKey_,
           Gost28147_89_Key maskKey_,
           Gost28147_89_MAC macKey_
        )
           : base()
        {
            encryptedKey = encryptedKey_;
            maskKey = maskKey_;
            macKey = macKey_;
        }

        /// <summary>
        /// This constructor is for required elements only.  It sets 
        /// all elements to references to the given objects
        /// </summary>
        public Gost28147_89_EncryptedKey(
           Gost28147_89_Key encryptedKey_,
           Gost28147_89_MAC macKey_
        )
           : base()
        {
            encryptedKey = encryptedKey_;
            macKey = macKey_;
        }

        /// <summary>
        /// This constructor allows primitive data to be passed for all 
        /// primitive elements.  It will create new object wrappers for 
        /// the primitive data and set other elements to references to 
        /// the given objects 
        /// </summary>
        public Gost28147_89_EncryptedKey(byte[] encryptedKey_,
           byte[] maskKey_,
           byte[] macKey_
        )
           : base()
        {
            encryptedKey = new Gost28147_89_Key(encryptedKey_);
            maskKey = new Gost28147_89_Key(maskKey_);
            macKey = new Gost28147_89_MAC(macKey_);
        }

        /// <summary>
        /// This constructor is for required elements only.  It allows 
        /// primitive data to be passed for all primitive elements.  
        /// It will create new object wrappers for the primitive data 
        /// and set other elements to references to the given objects. 
        /// </summary>
        public Gost28147_89_EncryptedKey(
           byte[] encryptedKey_,
           byte[] macKey_
        )
           : base()
        {
            encryptedKey = new Gost28147_89_Key(encryptedKey_);
            macKey = new Gost28147_89_MAC(macKey_);
        }

        public void Init()
        {
            encryptedKey = null;
            maskKey = null;
            macKey = null;
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

            if (context.MatchElemTag(Asn1Tag.Universal, Asn1Tag.PRIM, 4, elemLen, false))
            {
                encryptedKey = new Gost28147_89_Key();
                encryptedKey.Decode(buffer, true, elemLen.Value);
            }
            else
                throw new Exception("Asn1MissingRequiredException");

            // decode maskKey

            if (context.MatchElemTag(Asn1Tag.CTXT, Asn1Tag.PRIM, 0, elemLen, true))
            {
                maskKey = new Gost28147_89_Key();
                maskKey.Decode(buffer, false, elemLen.Value);
            }

            // decode macKey

            if (context.MatchElemTag(Asn1Tag.Universal, Asn1Tag.PRIM, 4, elemLen, false))
            {
                macKey = new Gost28147_89_MAC();
                macKey.Decode(buffer, true, elemLen.Value);
                if (!(macKey.Length == 4))
                {
                    throw new Exception("Asn1ConsVioException");
                }

            }
            else
                throw new Exception("Asn1MissingRequiredException");

        }

        public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
        {
            int _aal = 0, len;

            // encode macKey

            if (!(macKey.Length == 4))
            {
                throw new Exception("Asn1ConsVioException");
            }

            len = macKey.Encode(buffer, true);
            _aal += len;

            // encode maskKey

            if (maskKey != null)
            {
                len = maskKey.Encode(buffer, false);
                _aal += len;
                _aal += buffer.EncodeTagAndLength(Asn1Tag.CTXT, Asn1Tag.PRIM, 0, len);
            }

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
