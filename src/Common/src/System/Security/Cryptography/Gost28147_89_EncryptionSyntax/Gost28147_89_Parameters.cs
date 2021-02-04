namespace System.Security.Cryptography {

   class Gost28147_89_Parameters : Asn1OpenType {
      public Gost28147_89_IV iv;
      public Gost28147_89_ParamSet encryptionParamSet;

      public Gost28147_89_Parameters () : base()
      {
      }

      /// <summary>
      /// This constructor sets all elements to references to the 
      /// given objects
      /// </summary>
      public Gost28147_89_Parameters (
         Gost28147_89_IV iv_,
         Gost28147_89_ParamSet encryptionParamSet_
      )
         : base ()
      {
         iv = iv_;
         encryptionParamSet = encryptionParamSet_;
      }

      /// <summary>
      /// This constructor allows primitive data to be passed for all 
      /// primitive elements.  It will create new object wrappers for 
      /// the primitive data and set other elements to references to 
      /// the given objects 
      /// </summary>
      public Gost28147_89_Parameters (byte[] iv_,
         int[] encryptionParamSet_
      )
         : base ()
      {
         iv = new Gost28147_89_IV (iv_);
         encryptionParamSet = new Gost28147_89_ParamSet (encryptionParamSet_);
      }

      public void Init () {
         iv = null;
         encryptionParamSet = null;
      }

      public override void Decode
         (Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
      {
         int llen = (explicitTagging) ?
            MatchTag (buffer, Asn1Tag.Sequence) : implicitLength;

         Init ();

         // decode SEQUENCE

         Asn1BerDecodeContext context =
            new Asn1BerDecodeContext (buffer, llen);

         IntHolder elemLen = new IntHolder();

         // decode iv

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.PRIM, 4, elemLen, false)) {
            iv = new Gost28147_89_IV();
            iv.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

         // decode encryptionParamSet

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.PRIM, 6, elemLen, false)) {
            encryptionParamSet = new Gost28147_89_ParamSet();
            encryptionParamSet.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

      }

      public override int Encode (Asn1BerEncodeBuffer buffer, bool explicitTagging)
      {
         int _aal = 0, len;

         // encode encryptionParamSet

         len = encryptionParamSet.Encode (buffer, true);
         _aal += len;

         // encode iv

         len = iv.Encode (buffer, true);
         _aal += len;

         if (explicitTagging) {
            _aal += buffer.EncodeTagAndLength (Asn1Tag.Sequence, _aal);
         }

         return (_aal);
      }

   }
}
