namespace System.Security.Cryptography
{
   class AlgorithmIdentifier : Asn1Type {
      public Asn1ObjectIdentifier algorithm;
      public Asn1Type parameters;  // optional

      public AlgorithmIdentifier () : base()
      {
      }

      /// <summary>
      /// This constructor sets all elements to references to the 
      /// given objects
      /// </summary>
      public AlgorithmIdentifier (
         Asn1ObjectIdentifier algorithm_,
         Asn1Type parameters_
      )
         : base ()
      {
         algorithm = algorithm_;
         parameters = parameters_;
      }

      /// <summary>
      /// This constructor is for required elements only.  It sets 
      /// all elements to references to the given objects
      /// </summary>
      public AlgorithmIdentifier (
         Asn1ObjectIdentifier algorithm_
      )
         : base ()
      {
         algorithm = algorithm_;
      }

      /// <summary>
      /// This constructor allows primitive data to be passed for all 
      /// primitive elements.  It will create new object wrappers for 
      /// the primitive data and set other elements to references to 
      /// the given objects 
      /// </summary>
      public AlgorithmIdentifier (int[] algorithm_,
         Asn1Type parameters_
      )
         : base ()
      {
         algorithm = new Asn1ObjectIdentifier (algorithm_);
         parameters = parameters_;
      }

      /// <summary>
      /// This constructor is for required elements only.  It allows 
      /// primitive data to be passed for all primitive elements.  
      /// It will create new object wrappers for the primitive data 
      /// and set other elements to references to the given objects. 
      /// </summary>
      public AlgorithmIdentifier (
         int[] algorithm_
      )
         : base ()
      {
         algorithm = new Asn1ObjectIdentifier (algorithm_);
      }

      public void Init () {
         algorithm = null;
         parameters = null;
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

         if (context.MatchElemTag (Asn1Tag.Universal, Asn1Tag.PRIM, 6, elemLen, false)) {
            algorithm = new Asn1ObjectIdentifier();
            algorithm.Decode (buffer, true, elemLen.Value);
         }
         else throw new Exception("Asn1MissingRequiredException (buffer)");

         // decode parameters

         if (!context.Expired ()) {
            parameters = new Asn1OpenType();
            parameters.Decode (buffer, true, 0);
         }

         checkTC (true);
      }

      public override int Encode (Asn1BerEncodeBuffer buffer, bool explicitTagging)
      {
         int _aal = 0, len;

         checkTC (false);
         // encode parameters

         if (parameters != null) {
            len = parameters.Encode (buffer, true);
            _aal += len;
         }

         // encode algorithm

         len = algorithm.Encode (buffer, true);
         _aal += len;

         if (explicitTagging) {
            _aal += buffer.EncodeTagAndLength (Asn1Tag.Sequence, _aal);
         }

         return (_aal);
      }

      public void checkTC(bool decode)
      {
         /* check algorithm */
         ALGORITHM_ID _index = null;
         for(int i=0; i < _PKIX1Explicit88Values.SupportedAlgorithms.Length; i++) {
            if(_PKIX1Explicit88Values.SupportedAlgorithms[i].id.Equals(algorithm)) {
               _index = _PKIX1Explicit88Values.SupportedAlgorithms[i];
               break;
            }
         }
         if (null == _index) {
            return;
         }

         /* check parameters */
         if(decode) {
            if(parameters != null && _index.Type != null)
            {
               try {
                  Asn1BerDecodeBuffer buffer = new Asn1BerDecodeBuffer(((Asn1OpenType)parameters).Value);
                  parameters = (Asn1Type)System.Activator.CreateInstance(_index.Type.GetType());
                  parameters.Decode(buffer, Asn1Tag.EXPL, 0);
                  buffer.InvokeEndElement("parameters", -1);
               }
               catch (Exception e) {
                        //Asn1Util.WriteStackTrace(e, Console.Error);
                        //throw new Exception("Asn1Exception(table constraint: parameters decode failed)");
                        throw e;
               }
            }
         }
      }

   }
}
