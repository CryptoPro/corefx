namespace System.Security.Cryptography
{
   class _gost94DHPubKey_Type : Asn1Choice {
      // Choice element identifier constants
      public const byte _NULL_ = 1;
      public const byte _PARAMS_ = 2;

      public _gost94DHPubKey_Type () : base()
      {
      }

      public _gost94DHPubKey_Type (byte choiceId_, Asn1Type element_) : base()
      {
         SetElement (choiceId_, element_);
      }

      public override string ElemName {
         get {
            switch (ChoiceId) {
            case _NULL_: return "null_";
            case _PARAMS_: return "params_";
            default: return "UNDEFINED";
            }
         }
      }

      public void Set_null_ (NULLParams value) {
         SetElement (_NULL_, value);
      }

      public void Set_params_ (GostR3410_94_PublicKeyParameters value) {
         SetElement (_PARAMS_, value);
      }

      public override void Decode
         (Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
      {
         int llen = implicitLength;

         // decode CHOICE

         Asn1Tag tag = new Asn1Tag ();
         buffer.Mark ();
         int len = buffer.DecodeTagAndLength (tag);

         if (tag.Equals (Asn1Tag.Universal, Asn1Tag.PRIM, 5))
         {
            buffer.Reset();
            NULLParams null_ = new NULLParams();
            SetElement (_NULL_, null_);
            Element.Decode (buffer, true, len);
         }
         else if (tag.Equals (Asn1Tag.Universal, Asn1Tag.CONS, 16))
         {
            buffer.Reset();
            GostR3410_94_PublicKeyParameters params_ = new GostR3410_94_PublicKeyParameters();
            SetElement (_PARAMS_, params_);
            Element.Decode (buffer, true, len);
         }
         else {
            throw new Exception("Asn1InvalidChoiceOptionException (buffer, tag)");
         }
      }

      public override int Encode (Asn1BerEncodeBuffer buffer, bool explicitTagging)
      {
         int _aal = 0, len;
         switch (ChoiceId) {
         // encode null_
         case _NULL_:
            NULLParams null_ = (NULLParams) GetElement();
            len = null_.Encode (buffer, true);
            _aal += len;
            break;

         // encode params_
         case _PARAMS_:
            GostR3410_94_PublicKeyParameters params_ = (GostR3410_94_PublicKeyParameters) GetElement();
            len = params_.Encode (buffer, true);
            _aal += len;
            break;

         default:
            throw new Exception("Asn1InvalidChoiceOptionException()");
         }

         return _aal;
      }

   }
}
