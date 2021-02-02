namespace System.Security.Cryptography
{
   class SubjectPublicKeyInfo : Asn1Type {
      public AlgorithmIdentifier algorithm;
      public Asn1BitString subjectPublicKey;

      public SubjectPublicKeyInfo () : base()
      {
      }

      /// <summary>
      /// This constructor sets all elements to references to the 
      /// given objects
      /// </summary>
      public SubjectPublicKeyInfo (
         AlgorithmIdentifier algorithm_,
         Asn1BitString subjectPublicKey_
      )
         : base ()
      {
         algorithm = algorithm_;
         subjectPublicKey = subjectPublicKey_;
      }

      public void Init () {
         algorithm = null;
         subjectPublicKey = null;
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

         // decode algorithm

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.CONS, 16, elemLen, false)) {
            algorithm = new AlgorithmIdentifier();
            algorithm.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

         // decode subjectPublicKey

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.PRIM, 3, elemLen, false)) {
            subjectPublicKey = new Asn1BitString();
            subjectPublicKey.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

      }

      public override int Encode (Asn1BerEncodeBuffer buffer, bool explicitTagging)
      {
         int _aal = 0, len;

         // encode subjectPublicKey

         len = subjectPublicKey.Encode (buffer, true);
         _aal += len;

         // encode algorithm

         len = algorithm.Encode (buffer, true);
         _aal += len;

         if (explicitTagging) {
            _aal += buffer.EncodeTagAndLength (Asn1Tag.Sequence, _aal);
         }

         return (_aal);
      }

   }
}
