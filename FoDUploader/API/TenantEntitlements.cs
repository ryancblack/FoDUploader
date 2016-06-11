#region copyright
// Copyright (c) 2016 -  HPE Security Fortify on Demand, Ryan Black

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion 

using System.Collections.Generic;

namespace FoDUploader.API
{

    /// <summary>
    /// GET /api/v3/tenant-entitlements
    /// https://api.hpfod.com/swagger/ui/index#!/TenantEntitlements/TenantEntitlementsV3_Get
    /// </summary>
    public class TenantEntitlements
    {
        public int entitlementTypeId { get; set; }
        public string entitlementType { get; set; }
        public int subscriptionTypeId { get; set; }
        public string subscriptionType { get; set; }
        public List<TenantEntitlement> tenantEntitlements { get; set; }


        public class ExtendedProperties
        {
            public int assessmentTypeId { get; set; }
            public int frequencyTypeId { get; set; }
            public string frequencyType { get; set; }
            public string subscriptionLength { get; set; }
        }

        public class TenantEntitlement
        {
            public string entitlementId { get; set; }
            public int unitsPurchased { get; set; }
            public int unitsConsumed { get; set; }
            public string startDate { get; set; }
            public string endDate { get; set; }
            public ExtendedProperties extendedProperties { get; set; }
        }
    }
}
