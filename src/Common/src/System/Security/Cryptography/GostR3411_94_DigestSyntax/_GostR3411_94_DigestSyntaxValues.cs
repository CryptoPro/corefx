namespace System.Security.Cryptography
{
   class _GostR3411_94_DigestSyntaxValues {
      public static readonly int[] id_GostR3411_94 = { 1, 2, 643, 2, 2, 9 };
      public static readonly int[] id_GostR3411_94_TestParamSet = { 1, 2, 643, 2, 2, 30, 0 };
      public static readonly int[] id_GostR3411_94_CryptoProParamSet = { 1, 2, 643, 2, 2, 30, 1 };

      public static readonly AlgorithmIdentifier[] GostR3411_94_DigestAlgorithms = 
         new AlgorithmIdentifier[] {
            new AlgorithmIdentifier (
               new Asn1ObjectIdentifier(_GostR3411_94_DigestSyntaxValues.id_GostR3411_94),
               new Asn1Null()),
            new AlgorithmIdentifier (
               new Asn1ObjectIdentifier(_GostR3411_94_DigestSyntaxValues.id_GostR3411_94),
               new GostR3411_94_DigestParameters())
         };

   }
}
