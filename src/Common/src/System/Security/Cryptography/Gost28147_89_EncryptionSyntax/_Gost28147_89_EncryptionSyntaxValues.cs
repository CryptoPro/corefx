namespace System.Security.Cryptography
{
   class _Gost28147_89_EncryptionSyntaxValues {
      public static readonly int[] id_Gost28147_89 = { 1, 2, 643, 2, 2, 21 };
      public static readonly int[] id_Gost28147_89_MAC = { 1, 2, 643, 2, 2, 22 };
      public static readonly int[] id_tc26_cipher_gost_3412_2015_M = { 1, 2, 643, 7, 1, 1, 5, 1 };
      public static readonly int[] id_tc26_cipher_gost_3412_2015_K = { 1, 2, 643, 7, 1, 1, 5, 2 };
      public static readonly int[] id_Gost28147_89_TestParamSet = { 1, 2, 643, 2, 2, 31, 0 };
      public static readonly int[] id_Gost28147_89_CryptoPro_A_ParamSet = { 1, 2, 643, 2, 2, 31, 1 };
      public static readonly int[] id_Gost28147_89_CryptoPro_B_ParamSet = { 1, 2, 643, 2, 2, 31, 2 };
      public static readonly int[] id_Gost28147_89_CryptoPro_C_ParamSet = { 1, 2, 643, 2, 2, 31, 3 };
      public static readonly int[] id_Gost28147_89_CryptoPro_D_ParamSet = { 1, 2, 643, 2, 2, 31, 4 };
      public static readonly int[] id_Gost28147_89_CryptoPro_Oscar_1_1_ParamSet = { 1, 2, 643, 2, 2, 31, 5 };
      public static readonly int[] id_Gost28147_89_CryptoPro_Oscar_1_0_ParamSet = { 1, 2, 643, 2, 2, 31, 6 };
      public static readonly int[] id_Gost28147_89_CryptoPro_RIC_1_ParamSet = { 1, 2, 643, 2, 2, 31, 7 };
      public static readonly int[] id_Gost28147_89_TC26_A_ParamSet = { 1, 2, 643, 2, 2, 31, 12 };
      public static readonly int[] id_Gost28147_89_TC26_B_ParamSet = { 1, 2, 643, 2, 2, 31, 13 };
      public static readonly int[] id_Gost28147_89_TC26_C_ParamSet = { 1, 2, 643, 2, 2, 31, 14 };
      public static readonly int[] id_Gost28147_89_TC26_D_ParamSet = { 1, 2, 643, 2, 2, 31, 15 };
      public static readonly int[] id_Gost28147_89_TC26_E_ParamSet = { 1, 2, 643, 2, 2, 31, 16 };
      public static readonly int[] id_Gost28147_89_TC26_F_ParamSet = { 1, 2, 643, 2, 2, 31, 17 };
      public static readonly int[] id_tc26_gost_28147_paramSetISO = { 1, 2, 643, 7, 1, 2, 5, 1, 1 };

      public static readonly AlgorithmIdentifier[] Gost28147_89_Algorithms = 
         new AlgorithmIdentifier[] {
            new AlgorithmIdentifier (
               new Asn1ObjectIdentifier(_Gost28147_89_EncryptionSyntaxValues.id_Gost28147_89),
               new Gost28147_89_Parameters())
         };

   }
}
