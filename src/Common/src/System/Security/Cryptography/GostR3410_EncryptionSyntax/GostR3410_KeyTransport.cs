namespace System.Security.Cryptography
{
   class GostR3410_KeyTransport : Asn1Type {
      public Gost28147_89_EncryptedKey sessionEncryptedKey;
      public GostR3410_TransportParameters transportParameters;  // optional

      public GostR3410_KeyTransport () : base()
      {
      }

      /// <summary>
      /// This constructor sets all elements to references to the 
      /// given objects
      /// </summary>
      public GostR3410_KeyTransport (
         Gost28147_89_EncryptedKey sessionEncryptedKey_,
         GostR3410_TransportParameters transportParameters_
      )
         : base ()
      {
         sessionEncryptedKey = sessionEncryptedKey_;
         transportParameters = transportParameters_;
      }

      /// <summary>
      /// This constructor is for required elements only.  It sets 
      /// all elements to references to the given objects
      /// </summary>
      public GostR3410_KeyTransport (
         Gost28147_89_EncryptedKey sessionEncryptedKey_
      )
         : base ()
      {
         sessionEncryptedKey = sessionEncryptedKey_;
      }

      public void Init () {
         sessionEncryptedKey = null;
         transportParameters = null;
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

         // decode sessionEncryptedKey

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.CONS, 16, elemLen, false)) {
            sessionEncryptedKey = new Gost28147_89_EncryptedKey();
            sessionEncryptedKey.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

         // decode transportParameters

         if (context.MatchElemTag (Asn1Tag.CTXT, Asn1Tag.CONS, 0, elemLen, true)) {
            transportParameters = new GostR3410_TransportParameters();
            transportParameters.Decode (buffer, false, elemLen.Value);
         }

      }

      public override int Encode (Asn1BerEncodeBuffer buffer, bool explicitTagging)
      {
         int _aal = 0, len;

         // encode transportParameters

         if (transportParameters != null) {
            len = transportParameters.Encode (buffer, false);
            _aal += len;
            _aal += buffer.EncodeTagAndLength (Asn1Tag.CTXT, Asn1Tag.CONS, 0, len);
         }

         // encode sessionEncryptedKey

         len = sessionEncryptedKey.Encode (buffer, true);
         _aal += len;

         if (explicitTagging) {
            _aal += buffer.EncodeTagAndLength (Asn1Tag.Sequence, _aal);
         }

         return (_aal);
      }

   }
}
