namespace System.Security.Cryptography
{
    class Gost28147_89_KeyWrapParameters : Asn1Type
    {
        public Gost28147_89_ParamSet encryptionParamSet;
        public Asn1OctetString ukm;  // optional

        public Gost28147_89_KeyWrapParameters() : base()
        {
        }

        /// <summary>
        /// This constructor sets all elements to references to the 
        /// given objects
        /// </summary>
        public Gost28147_89_KeyWrapParameters(
           Gost28147_89_ParamSet encryptionParamSet_,
           Asn1OctetString ukm_
        )
           : base()
        {
            encryptionParamSet = encryptionParamSet_;
            ukm = ukm_;
        }

        /// <summary>
        /// This constructor is for required elements only.  It sets 
        /// all elements to references to the given objects
        /// </summary>
        public Gost28147_89_KeyWrapParameters(
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
        public Gost28147_89_KeyWrapParameters(int[] encryptionParamSet_,
           byte[] ukm_
        )
           : base()
        {
            encryptionParamSet = new Gost28147_89_ParamSet(encryptionParamSet_);
            ukm = new Asn1OctetString(ukm_);
        }

        /// <summary>
        /// This constructor is for required elements only.  It allows 
        /// primitive data to be passed for all primitive elements.  
        /// It will create new object wrappers for the primitive data 
        /// and set other elements to references to the given objects. 
        /// </summary>
        public Gost28147_89_KeyWrapParameters(
           int[] encryptionParamSet_
        )
           : base()
        {
            encryptionParamSet = new Gost28147_89_ParamSet(encryptionParamSet_);
        }

        public void Init()
        {
            encryptionParamSet = null;
            ukm = null;
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

            // decode ukm

            if (context.MatchElemTag(Asn1Tag.Universal, Asn1Tag.PRIM, 4, elemLen, false))
            {
                ukm = new Asn1OctetString();
                ukm.Decode(buffer, true, elemLen.Value);
                if (!(ukm.Length == 8))
                {
                    throw new Exception("Asn1ConsVioException");
                }

            }

        }

        public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
        {
            int _aal = 0, len;

            // encode ukm

            if (ukm != null)
            {
                if (!(ukm.Length == 8))
                {
                    throw new Exception("Asn1ConsVioException");
                }

                len = ukm.Encode(buffer, true);
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
