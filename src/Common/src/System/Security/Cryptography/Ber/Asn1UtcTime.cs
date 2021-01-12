// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Text;

namespace System.Security.Cryptography
{
	[Serializable]
	class Asn1UtcTime : Asn1Time
	{
		public static readonly Asn1Tag Tag = new Asn1Tag(0, 0, UtcTimeTypeCode);


		public Asn1UtcTime()
			: base(UtcTimeTypeCode, false)
		{
		}

		public Asn1UtcTime(bool useDerRules)
			: base(UtcTimeTypeCode, useDerRules)
		{
		}

		public Asn1UtcTime(string data)
			: base(data, UtcTimeTypeCode, false)
		{
		}

		public Asn1UtcTime(string data, bool useDerRules)
			: base(data, UtcTimeTypeCode, useDerRules)
		{
		}


		public override string Fraction
		{
			get
			{
				return "";
			}
			set
			{
				SecFraction = "";

				throw new FormatException("Asn1FractionNotSupportedForUtcTime");

            }
		}

		public override int Year
		{
			get
			{
				if (!Parsed)
				{
					ParseString(Value);
				}

				return YearValue;
			}
			set
			{
				if (value < 0)
				{
					throw new FormatException("Asn1InvalidYearValue");

                }

				if (value < 100)
				{
					if (value >= 50)
					{
						Year = value + 0x76c;
					}
					else
					{
						Year = value + 0x7d0;
					}
				}

				Year = value;
			}
		}

		public override void Clear()
		{
			Clear();
			HourValue = MinuteValue = -1;
			UtcFlag = true;
		}

		public override int CompareTo(object obj)
		{
			return base.CompareTo(obj);
		}

		protected override bool CompileString()
		{
			Value = "";

			if (((YearValue < 0) || (DayValue <= 0)) || (((MonthValue <= 0) || (HourValue < 0)) || (MinuteValue < 0)))
			{
				return false;
			}

			if (StringBuffer == null)
			{
				StringBuffer = new StringBuilder();
			}
			else
			{
				StringBuffer.Length = 0;
			}

			if ((DerRules || UtcFlag) && ((DiffHourValue != 0) || (DiffMinValue != 0)))
			{
				var time = GetTime();
				time.AddMinutes(-DiffMinValue);
				time.AddHours(-DiffHourValue);

				PutInteger(2, time.Year);
				PutInteger(2, time.Month);
				PutInteger(2, time.Day);
				PutInteger(2, time.Hour);
				PutInteger(2, time.Minute);
			}
			else
			{
				PutInteger(2, YearValue);
				PutInteger(2, MonthValue);
				PutInteger(2, DayValue);
				PutInteger(2, HourValue);
				PutInteger(2, MinuteValue);
			}

			PutInteger(2, SecondValue);

			if (DerRules || UtcFlag)
			{
				StringBuffer.Append('Z');
			}
			else if ((DiffHourValue != 0) || (DiffMinValue != 0))
			{
				StringBuffer.Append((DiffHourValue > 0) ? '+' : '-');
				PutInteger(2, Math.Abs(DiffHourValue));
				PutInteger(2, Math.Abs(DiffMinValue));
			}

			Value = StringBuffer.ToString();

			return true;
		}

		public override void Decode(Asn1BerDecodeBuffer buffer, bool explicitTagging, int implicitLength)
		{
			Decode(buffer, explicitTagging, implicitLength, Tag);
		}

		public override int Encode(Asn1BerEncodeBuffer buffer, bool explicitTagging)
		{
			return Encode(buffer, explicitTagging, Tag);
		}

		public override void Encode(Asn1BerOutputStream outs, bool explicitTagging)
		{
			Encode(outs, explicitTagging, Tag);
		}

		protected override void Init()
		{
			Init();
			HourValue = MinuteValue = -1;
			UtcFlag = true;
		}

		public override void ParseString(string data)
		{
			if (data == null)
			{
                throw new ArgumentNullException(nameof(data));
            }

			Clear();

			var off = new IntHolder(0);

			try
			{
				YearValue = ParseInt(data, off, 2);
				MonthValue = ParseInt(data, off, 2);
				DayValue = ParseInt(data, off, 2);

				if (YearValue < 0)
				{
					throw new FormatException("Asn1InvalidYearValue");

                }

				if (YearValue < 100)
				{
					if (YearValue > 70)
					{
						YearValue += 0x76c;
					}
					else
					{
						YearValue += 0x7d0;
					}
				}

				if ((MonthValue < 1) || (MonthValue > 12))
				{
					throw new FormatException("Asn1InvalidMonthValue");

                }

				var num = DaysInMonth[MonthValue];

				if (((MonthValue == 2) && ((YearValue % 4) == 0)) && (((YearValue % 100) != 0) || ((YearValue % 400) == 0)))
				{
					num++;
				}

				if ((DayValue < 1) || (DayValue > num))
				{
					throw new FormatException("Asn1InvalidDayValue");

                }

				var num2 = 0;

				if (!char.IsDigit(CharAt(data, off.Value)))
				{
					throw new FormatException("Asn1HoursExpected");

                }

				HourValue = ParseInt(data, off, 2);
				num2++;

				if (!char.IsDigit(CharAt(data, off.Value)))
				{
					throw new FormatException("Resources.Asn1MinutesExpected");

                }

				MinuteValue = ParseInt(data, off, 2);
				num2++;

				if (char.IsDigit(CharAt(data, off.Value)))
				{
					SecondValue = ParseInt(data, off, 2);
					num2++;
				}

				if ((num2 >= 2) && ((HourValue < 0) || (HourValue > UtcTimeTypeCode)))
				{
					throw new FormatException("Asn1InvalidHourValue");

                }

				if ((num2 >= 2) && ((MinuteValue < 0) || (MinuteValue > 0x3b)))
				{
					throw new FormatException("Asn1InvalidMinuteValue");

                }

				if ((num2 == 3) && ((SecondValue < 0) || (SecondValue > 0x3b)))
				{
					throw new FormatException("Asn1InvalidSecondValue");

                }

				CharAt(data, off.Value);

				if (CharAt(data, off.Value) == 'Z')
				{
					off.Value++;
					UtcFlag = true;

					if (off.Value != data.Length)
					{
						throw new FormatException("Asn1UnexpectedValuesAtEndOfString");

                    }
				}
				else
				{
					if (DerRules)
					{
						throw new FormatException("Asn1UnexpectedZoneOffset");

                    }

					UtcFlag = false;
					var ch = CharAt(data, off.Value);

					switch (ch)
					{
						case '-':
						case '+':
							off.Value++;

							if (!char.IsDigit(CharAt(data, off.Value)))
							{
								throw new FormatException("Asn1InvalidDiffHour");

                            }

							DiffHourValue = ParseInt(data, off, 2);

							if (!char.IsDigit(CharAt(data, off.Value)))
							{
								throw new FormatException("Asn1InvalidDiffMinute");

                            }

							DiffMinValue = ParseInt(data, off, 2);

							if ((DiffHourValue < 0) || (DiffHourValue > 12))
							{
								throw new FormatException("Resources.Asn1InvalidDiffHourValue");

                            }

							if ((DiffMinValue < 0) || (DiffMinValue > 0x3b))
							{
								throw new FormatException("Asn1InvalidDiffMinuteValue");

                            }

							if (ch == '-')
							{
								DiffHourValue = -DiffHourValue;
								DiffMinValue = -DiffMinValue;
							}
							break;
					}
				}

				Parsed = true;

				if (data != Value)
				{
					CompileString();
				}
			}
			catch (IndexOutOfRangeException)
			{
				throw new FormatException("Asn1InvalidDateFormat");

            }
			catch (FormatException)
			{
				throw new FormatException("Asn1InvalidNumberFormat");

            }
			catch (ArgumentException)
			{
				throw new FormatException("Asn1InvalidDateFormat");

            }
		}

		public override void SetTime(DateTime time)
		{
			Clear();
			YearValue = time.Year;
			MonthValue = time.Month;
			DayValue = time.Day;
			HourValue = time.Hour;
			MinuteValue = time.Minute;
			SecondValue = time.Second;
			SecFraction = "";
			DiffHourValue = DiffMinValue = 0;
			UtcFlag = true;
			CompileString();
		}
	}
}
