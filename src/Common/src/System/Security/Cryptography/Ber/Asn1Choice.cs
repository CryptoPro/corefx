﻿namespace System.Security.Cryptography
{
	[Serializable]
	abstract class Asn1Choice : Asn1Type
	{
		[NonSerialized]
		private int _choiceId;

		[NonSerialized]
		protected Asn1Type Element;


		public virtual int ChoiceId
		{
			get { return _choiceId; }
		}

		public abstract string ElemName { get; }

		public override bool Equals(object value)
		{
			var choice = value as Asn1Choice;

			if (choice == null)
			{
				return false;
			}

			if (_choiceId != choice._choiceId)
			{
				return false;
			}

			return Element.Equals(choice.Element);
		}

		public virtual Asn1Type GetElement()
		{
			return Element;
		}

		public override int GetHashCode()
		{
			return (Element != null) ? Element.GetHashCode() : base.GetHashCode();
		}

		public virtual void SetElement(int choiceId, Asn1Type element)
		{
			_choiceId = choiceId;

			Element = element;
		}
	}
}
