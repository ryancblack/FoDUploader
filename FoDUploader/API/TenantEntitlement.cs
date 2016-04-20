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
