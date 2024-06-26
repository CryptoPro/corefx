// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

namespace System.ComponentModel.DataAnnotations
{
    [AttributeUsage(AttributeTargets.Property | AttributeTargets.Field | AttributeTargets.Parameter,
        AllowMultiple = false)]
    public sealed class EmailAddressAttribute : DataTypeAttribute
    {
        private static readonly char[] s_newLines = new char[] { '\r', '\n' };
        private static bool s_allowFullDomainLiterals =
            AppContext.TryGetSwitch("System.Net.AllowFullDomainLiterals", out bool enable) ? enable : false;

        public EmailAddressAttribute()
            : base(DataType.EmailAddress)
        {
            // Set DefaultErrorMessage not ErrrorMessage, allowing user to set
            // ErrorMessageResourceType and ErrorMessageResourceName to use localized messages.
            DefaultErrorMessage = SR.EmailAddressAttribute_Invalid;
        }

        public override bool IsValid(object value)
        {
            if (value == null)
            {
                return true;
            }

            if (!(value is string valueAsString))
            {
                return false;
            }

            if (!s_allowFullDomainLiterals && valueAsString.IndexOfAny(s_newLines) >= 0)
            {
                return false;
            }

            // only return true if there is only 1 '@' character
            // and it is neither the first nor the last character
            int index = valueAsString.IndexOf('@');
            
            return
                index > 0 &&
                index != valueAsString.Length - 1 &&
                index == valueAsString.LastIndexOf('@');
        }
    }
}
