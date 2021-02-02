namespace System.Security.Cryptography
{
   class _GostR3410_94_PKISyntaxValues {
      public static readonly int[] id_GostR3410_94 = { 1, 2, 643, 2, 2, 20 };
      public static readonly int[] id_GostR3410_94DH = { 1, 2, 643, 2, 2, 99 };
      public static readonly int[] id_GostR3411_94_with_GostR3410_94 = { 1, 2, 643, 2, 2, 4 };
      public static readonly int[] id_GostR3410_94_TestParamSet = { 1, 2, 643, 2, 2, 32, 0 };
      public static readonly int[] id_GostR3410_94_CryptoPro_A_ParamSet = { 1, 2, 643, 2, 2, 32, 2 };
      public static readonly int[] id_GostR3410_94_CryptoPro_B_ParamSet = { 1, 2, 643, 2, 2, 32, 3 };
      public static readonly int[] id_GostR3410_94_CryptoPro_C_ParamSet = { 1, 2, 643, 2, 2, 32, 4 };
      public static readonly int[] id_GostR3410_94_CryptoPro_D_ParamSet = { 1, 2, 643, 2, 2, 32, 5 };
      public static readonly int[] id_GostR3410_94_CryptoPro_XchA_ParamSet = { 1, 2, 643, 2, 2, 33, 1 };
      public static readonly int[] id_GostR3410_94_CryptoPro_XchB_ParamSet = { 1, 2, 643, 2, 2, 33, 2 };
      public static readonly int[] id_GostR3410_94_CryptoPro_XchC_ParamSet = { 1, 2, 643, 2, 2, 33, 3 };

      public static readonly AlgorithmIdentifier[] GostR3410_94_PublicKeyAlgorithms = 
         new AlgorithmIdentifier[] {
            new AlgorithmIdentifier (
               new Asn1ObjectIdentifier(_GostR3410_94_PKISyntaxValues.id_GostR3410_94),
               new GostR3410_94_PublicKeyParameters())
         };

   }
}
