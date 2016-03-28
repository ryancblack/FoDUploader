using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoDUploader.API
{
    class ReleaseResponse
    {
        public Data data { get; set; }
        public int responseCode { get; set; }

    }
    class Data
    {
        //https://hpfod.com/api/v1/Release/{releaseId}

        public int applicationId { get; set; }
        public int releaseId { get; set; }
        public string applicationName { get; set; }
        public string releaseName { get; set; }
        public int status { get; set; }
        public int rating { get; set; }
        public int critical { get; set; }
        public int high { get; set; }
        public int medium { get; set; }
        public int low { get; set; }
        public int scanStatus { get; set; }
        public int currentStaticScanId { get; set; }
        public int currentDynamicScanId { get; set; }
        public int currentMobileScanId { get; set; }
        public string dynamicScanStatus { get; set; }
        public int staticScanStatus { get; set; }
        public int mobileScanStatus { get; set; }
        public int dynamicScanStatusId { get; set; }
        public int staticScanStatusId { get; set; }
        public int mobileScanStatusId { get; set; }
        public DateTime dynamicScanDate { get; set; }
        public DateTime staticScanDate { get; set; }
        public DateTime mobileScanDate { get; set; }
        public int issueCount { get; set; }
        public bool isPassed { get; set; }
        public int passFailReasonId { get; set; }
        public int releaseSDLCStatusId { get; set; }
        public string releaseSDLCStatusValue { get; set; }
    }
}
