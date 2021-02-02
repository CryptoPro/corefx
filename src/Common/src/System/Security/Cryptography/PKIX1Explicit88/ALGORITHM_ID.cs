namespace System.Security.Cryptography
{

   class ALGORITHM_ID {
      public Asn1ObjectIdentifier id;
      public Asn1Type Type;

      public ALGORITHM_ID() {
         id = null;
         Type = null;
      }

      public ALGORITHM_ID(
         Asn1ObjectIdentifier id_,
         Asn1Type Type_
         ) {
         id = id_;
         Type = Type_;
      }
   }
}
