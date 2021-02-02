namespace System.Security.Cryptography
{
   class _PKIX1Explicit88Values {

      public static readonly ALGORITHM_ID gost94PubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_94_PKISyntaxValues.id_GostR3410_94),
            new _gost94PubKey_Type());

      public static readonly ALGORITHM_ID gost94DHPubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_94_PKISyntaxValues.id_GostR3410_94DH),
            new _gost94DHPubKey_Type());

      public static readonly ALGORITHM_ID gost94WithGostR341094SigParams = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_94_PKISyntaxValues.id_GostR3411_94_with_GostR3410_94),
            new GostR3410_94_PublicKeyParameters());

      public static readonly ALGORITHM_ID gost94WithGostR341094SigNULLParams = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_94_PKISyntaxValues.id_GostR3411_94_with_GostR3410_94),
            new NULLParams());

      public static readonly ALGORITHM_ID gost2001PubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2001_PKISyntaxValues.id_GostR3410_2001),
            new _gost2001PubKey_Type());

      public static readonly ALGORITHM_ID gost2001DHPubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2001_PKISyntaxValues.id_GostR3410_2001DH),
            new _gost2001DHPubKey_Type());

      public static readonly ALGORITHM_ID gost2012_256_PubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2012_PKISyntaxValues.id_tc26_gost3410_2012_256),
            new _gost2012_256_PubKey_Type());

      public static readonly ALGORITHM_ID gost2012_256DH_PubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2012_PKISyntaxValues.id_tc26_gost3410_2012_256_dh),
            new _gost2012_256DH_PubKey_Type());

      public static readonly ALGORITHM_ID gost2012_512_PubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2012_PKISyntaxValues.id_tc26_gost3410_2012_512),
            new _gost2012_512_PubKey_Type());

      public static readonly ALGORITHM_ID gost2012_512DH_PubKey = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2012_PKISyntaxValues.id_tc26_gost3410_2012_512_dh),
            new _gost2012_512DH_PubKey_Type());

      public static readonly ALGORITHM_ID gost2001WithGostR341094SigNULLParams = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2001_PKISyntaxValues.id_GostR3411_94_with_GostR3410_2001),
            new NULLParams());

      public static readonly ALGORITHM_ID gost12_256_WithGostR34102012_256_Sign = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2012_PKISyntaxValues.id_tc26_signwithdigest_gost3410_2012_256),
            new NULLParams());

      public static readonly ALGORITHM_ID gost12_512_WithGostR34102012_512_Sign = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3410_2012_PKISyntaxValues.id_tc26_signwithdigest_gost3410_2012_512),
            new NULLParams());

      public static readonly ALGORITHM_ID gost2814789Params = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_Gost28147_89_EncryptionSyntaxValues.id_Gost28147_89),
            new Gost28147_89_Parameters());

      public static readonly ALGORITHM_ID gostR341194DigestParams = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3411_94_DigestSyntaxValues.id_GostR3411_94),
            new _gostR341194DigestParams_Type());

      public static readonly ALGORITHM_ID gostR341112_256_DigestParams = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3411_2012_DigestSyntaxValues.id_tc26_gost3411_2012_256),
            new NULLParams());

      public static readonly ALGORITHM_ID gostR341112_512_DigestParams = 
         new ALGORITHM_ID (
            new Asn1ObjectIdentifier(_GostR3411_2012_DigestSyntaxValues.id_tc26_gost3411_2012_512),
            new NULLParams());

      public static readonly ATTRIBUTE_CLASS[] SupportedAttributes = 
         new ATTRIBUTE_CLASS[] {
         };

      public static readonly ALGORITHM_ID[] SupportedAlgorithms = 
         new ALGORITHM_ID[] {
            _PKIX1Explicit88Values.gost94PubKey,
            _PKIX1Explicit88Values.gost94DHPubKey,
            _PKIX1Explicit88Values.gost2012_256_PubKey,
            _PKIX1Explicit88Values.gost2012_512_PubKey,
            _PKIX1Explicit88Values.gost12_256_WithGostR34102012_256_Sign,
            _PKIX1Explicit88Values.gost12_512_WithGostR34102012_512_Sign,
            _PKIX1Explicit88Values.gost94WithGostR341094SigNULLParams,
            _PKIX1Explicit88Values.gost2001PubKey,
            _PKIX1Explicit88Values.gost2001DHPubKey,
            _PKIX1Explicit88Values.gost2001WithGostR341094SigNULLParams,
            _PKIX1Explicit88Values.gost2814789Params,
            _PKIX1Explicit88Values.gostR341194DigestParams,
            _PKIX1Explicit88Values.gostR341112_256_DigestParams,
            _PKIX1Explicit88Values.gostR341112_512_DigestParams
         };

   }
}
