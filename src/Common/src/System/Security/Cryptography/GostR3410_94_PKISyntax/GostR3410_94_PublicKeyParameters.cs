namespace System.Security.Cryptography
{
   class GostR3410_94_PublicKeyParameters : Asn1OpenType {
      public Asn1ObjectIdentifier publicKeyParamSet;
      public Asn1ObjectIdentifier digestParamSet;
      public Gost28147_89_ParamSet encryptionParamSet;  // optional

      public GostR3410_94_PublicKeyParameters () : base()
      {
      }

      /// <summary>
      /// This constructor sets all elements to references to the 
      /// given objects
      /// </summary>
      public GostR3410_94_PublicKeyParameters (
         Asn1ObjectIdentifier publicKeyParamSet_,
         Asn1ObjectIdentifier digestParamSet_,
         Gost28147_89_ParamSet encryptionParamSet_
      )
         : base ()
      {
         publicKeyParamSet = publicKeyParamSet_;
         digestParamSet = digestParamSet_;
         encryptionParamSet = encryptionParamSet_;
      }

      /// <summary>
      /// This constructor is for required elements only.  It sets 
      /// all elements to references to the given objects
      /// </summary>
      public GostR3410_94_PublicKeyParameters (
         Asn1ObjectIdentifier publicKeyParamSet_,
         Asn1ObjectIdentifier digestParamSet_
      )
         : base ()
      {
         publicKeyParamSet = publicKeyParamSet_;
         digestParamSet = digestParamSet_;
      }

      /// <summary>
      /// This constructor allows primitive data to be passed for all 
      /// primitive elements.  It will create new object wrappers for 
      /// the primitive data and set other elements to references to 
      /// the given objects 
      /// </summary>
      public GostR3410_94_PublicKeyParameters (int[] publicKeyParamSet_,
         int[] digestParamSet_,
         int[] encryptionParamSet_
      )
         : base ()
      {
         publicKeyParamSet = new Asn1ObjectIdentifier (publicKeyParamSet_);
         digestParamSet = new Asn1ObjectIdentifier (digestParamSet_);
         encryptionParamSet = new Gost28147_89_ParamSet (encryptionParamSet_);
      }

      /// <summary>
      /// This constructor is for required elements only.  It allows 
      /// primitive data to be passed for all primitive elements.  
      /// It will create new object wrappers for the primitive data 
      /// and set other elements to references to the given objects. 
      /// </summary>
      public GostR3410_94_PublicKeyParameters (
         int[] publicKeyParamSet_,
         int[] digestParamSet_
      )
         : base ()
      {
         publicKeyParamSet = new Asn1ObjectIdentifier (publicKeyParamSet_);
         digestParamSet = new Asn1ObjectIdentifier (digestParamSet_);
      }

      public void Init () {
         publicKeyParamSet = null;
         digestParamSet = null;
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

         // decode publicKeyParamSet

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.PRIM, 6, elemLen, false)) {
            publicKeyParamSet = new Asn1ObjectIdentifier();
            publicKeyParamSet.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

         // decode digestParamSet

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.PRIM, 6, elemLen, false)) {
            digestParamSet = new Asn1ObjectIdentifier();
            digestParamSet.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

         // decode encryptionParamSet

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.PRIM, 6, elemLen, false)) {
            encryptionParamSet = new Gost28147_89_ParamSet();
            encryptionParamSet.Decode (buffer, true, elemLen.Value);
         }

      }

      public override int Encode (Asn1BerEncodeBuffer buffer, bool explicitTagging)
      {
         int _aal = 0, len;

         // encode encryptionParamSet

         if (encryptionParamSet != null) {
            len = encryptionParamSet.Encode (buffer, true);
            _aal += len;
         }

         // encode digestParamSet

         len = digestParamSet.Encode (buffer, true);
         _aal += len;

         // encode publicKeyParamSet

         len = publicKeyParamSet.Encode (buffer, true);
         _aal += len;

         if (explicitTagging) {
            _aal += buffer.EncodeTagAndLength (Asn1Tag.Sequence, _aal);
         }

         return (_aal);
      }

   }
}
