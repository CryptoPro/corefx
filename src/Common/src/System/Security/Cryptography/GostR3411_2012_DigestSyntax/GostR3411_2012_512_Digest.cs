namespace System.Security.Cryptography
{

   class GostR3411_2012_512_Digest : Asn1OctetString {
      public GostR3411_2012_512_Digest () : base()
      {
      }

      /// <summary>
      /// This constructor initializes an octet string from the given 
      /// byte array by setting the 'value' public member variable in the 
      /// base class to the given value.
      /// </summary>
      /// <param name="data"> Byte array containing an octet string 
      /// in binary form. </param>
      public GostR3411_2012_512_Digest (byte[] data) : base (data)
      {
      }

      /// <summary>
      /// This constructor initializes an octet string from a portion 
      /// of the given byte array.  A new byte array is created starting 
      /// at the given offset and consisting of the given number of bytes.
      /// </summary>
      /// <param name="data"> Byte array containing an octet string 
      /// in binary form.</param>
      /// <param name="offset"> Starting offset in data from which to copy bytes</param>
      /// <param name="nbytes"> Number of bytes to copy from target array</param>
      public GostR3411_2012_512_Digest (byte[] data, int offset, int nbytes) :
         base (data, offset, nbytes)
      {
      }

      /// <summary>
      /// This constructor parses the given ASN.1 value text (either a 
      /// binary or hex data string) and assigns the values to the internal
      /// bit string.
      ///
      /// Examples of valid value formats are as follows:
      /// Binary string:    "'11010010111001'B"
      /// Hex string:       "'0fa56920014abc'H"
      /// Char string:      "'abcdefg'"
      ///
      /// Note: if the text contains no internal single-quote
      /// Marks ('), it is assumed to be a character string.
      /// </summary>
      /// <param name="value"> The ASN.1 value specification text</param>
      public GostR3411_2012_512_Digest (string value) : base (value)
      {
      }

      public override void Decode
         (Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
      {
         base.Decode (buffer, explicitTagging, implicitLength);
         if (!(Length == 64)) {
            throw new Exception("Asn1ConsVioException (Length, Length)");
         }

      }

      public override int Encode (Asn1BerEncodeBuffer buffer, bool explicitTagging)
      {
         if (!(Length == 64)) {
            throw new Exception("Asn1ConsVioException (Length, Length)");
         }

         int _aal = base.Encode (buffer, false);

         if (explicitTagging) {
            _aal += buffer.EncodeTagAndLength (Tag, _aal);
         }

         return (_aal);
      }

   }
}
