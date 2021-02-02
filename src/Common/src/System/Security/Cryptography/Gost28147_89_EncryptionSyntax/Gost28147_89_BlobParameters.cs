namespace System.Security.Cryptography
{
    class Gost28147_89_BlobParameters : Asn1Type
    {
        public Gost28147_89_ParamSet encryptionParamSet;
        public Asn1OpenExt extElem1;

        public Gost28147_89_BlobParameters() : base()
        {
        }

        /// <summary>
        /// This constructor sets all elements to references to the 
        /// given objects
        /// </summary>
        public Gost28147_89_BlobParameters(
           Gost28147_89_ParamSet encryptionParamSet_
        )
           : base()
        {
            encryptionParamSet = encryptionParamSet_;
        }

        /// <summary>
        /// This constructor allows primitive data to be passed for all 
        /// primitive elements.  It will create new object wrappers for 
        /// the primitive data and set other elements to references to 
        /// the given objects 
        /// </summary>
        public Gost28147_89_BlobParameters(int[] encryptionParamSet_
        )
           : base()
        {
            encryptionParamSet = new Gost28147_89_ParamSet(encryptionParamSet_);
        }

        public void Init()
        {
            encryptionParamSet = null;
            extElem1 = null;
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

            // decode encryptionParamSet

            if (context.MatchElemTag(Asn1Tag.Universal, Asn1Tag.PRIM, 6, elemLen, false))
            {
                encryptionParamSet = new Gost28147_89_ParamSet();
                encryptionParamSet.Decode(buffer, true, elemLen.Value);
            }
            else
                throw new Exception("Asn1MissingRequiredException");

            // decode extElem1

            if (!context.Expired())
            {
                Asn1Tag _tag = buffer.PeekTag();
                if (_tag.Equals(Asn1Tag.Universal, Asn1Tag.PRIM, 6))
                {
                    throw new Exception("Asn1SeqOrderException");
                }
                else
                {
                    extElem1 = new Asn1OpenExt();
                    while (!context.Expired())
                    {
                        extElem1.DecodeComponent(buffer);
                    }
                }
            }
            else
                extElem1 = null;

        }

        public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
        {
            int _aal = 0, len;

            // encode extElem1

            if (extElem1 != null)
            {
                len = extElem1.Encode(buffer, false);
                _aal += len;
            }

            // encode encryptionParamSet

            len = encryptionParamSet.Encode(buffer, true);
            _aal += len;

            if (explicitTagging)
            {
                _aal += buffer.EncodeTagAndLength(Asn1Tag.Sequence, _aal);
            }

            return (_aal);
        }

    }
}
