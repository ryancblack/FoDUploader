#region copyright
// Copyright (c) 2016 -  Ryan Black - ryanblack@gmail.com

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion 

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoDUploader.API
{
    public class TenantEntitlement
    {
        public int entitlementId { get; set; }
        public int unitsPurchased { get; set; }
        public int unitsConsumed { get; set; }
        public DateTime startDate { get; set; }
        public DateTime endDate { get; set; }
        public int assessmentTypeId { get; set; }
        public int frequencyTypeId { get; set; }
        public string subscriptionLength { get; set; }
    }
    public class TenantEntitlementResponse
    {
        public int entitlementTypeId { get; set; }
        public int subscriptionTypeId { get; set; }
        public List<TenantEntitlement> tenantEntitlements { get; set; }
    }

    public class TenantEntitlementQuery
    {
        public TenantEntitlementResponse data { get; set; }
        public int responseCode { get; set; }
        public int errorCode { get; set; }
        public object message { get; set; }
        public object links { get; set; }
    }
}
