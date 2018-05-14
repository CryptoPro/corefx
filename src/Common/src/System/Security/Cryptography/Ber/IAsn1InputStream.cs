﻿namespace System.Security.Cryptography
{
	interface IAsn1InputStream
	{
		int Available();
		void Close();
		void Mark();
		bool MarkSupported();
		void Reset();
		long Skip(long nbytes);
	}
}
