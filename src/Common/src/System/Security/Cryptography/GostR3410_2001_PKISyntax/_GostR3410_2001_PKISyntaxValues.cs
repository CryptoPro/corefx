namespace System.Security.Cryptography
{
   class _GostR3410_2001_PKISyntaxValues {
      public static readonly int[] id_GostR3410_2001 = { 1, 2, 643, 2, 2, 19 };
      public static readonly int[] id_GostR3410_2001DH = { 1, 2, 643, 2, 2, 98 };
      public static readonly int[] id_GostR3411_94_with_GostR3410_2001 = { 1, 2, 643, 2, 2, 3 };
      public static readonly int[] id_GostR3410_2001_TestParamSet = { 1, 2, 643, 2, 2, 35, 0 };
      public static readonly int[] id_GostR3410_2001_CryptoPro_A_ParamSet = { 1, 2, 643, 2, 2, 35, 1 };
      public static readonly int[] id_GostR3410_2001_CryptoPro_B_ParamSet = { 1, 2, 643, 2, 2, 35, 2 };
      public static readonly int[] id_GostR3410_2001_CryptoPro_C_ParamSet = { 1, 2, 643, 2, 2, 35, 3 };
      public static readonly int[] id_GostR3410_2001_CryptoPro_XchA_ParamSet = { 1, 2, 643, 2, 2, 36, 0 };
      public static readonly int[] id_GostR3410_2001_CryptoPro_XchB_ParamSet = { 1, 2, 643, 2, 2, 36, 1 };

      public static readonly AlgorithmIdentifier[] GostR3410_2001_PublicKeyAlgorithms = 
         new AlgorithmIdentifier[] {
            new AlgorithmIdentifier (
               new Asn1ObjectIdentifier(_GostR3410_2001_PKISyntaxValues.id_GostR3410_2001),
               new GostR3410_2001_PublicKeyParameters())
         };

   }
}
