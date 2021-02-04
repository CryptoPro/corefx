namespace System.Security.Cryptography
{
   class ATTRIBUTE_CLASS {
      public Asn1Type Type;
      public Asn1ObjectIdentifier id;

      public ATTRIBUTE_CLASS() {
         Type = null;
         id = null;
      }

      public ATTRIBUTE_CLASS(
         Asn1Type Type_,
         Asn1ObjectIdentifier id_
         ) {
         Type = Type_;
         id = id_;
      }
   }
}
