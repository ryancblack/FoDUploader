#region copyright
// Copyright (c) 2016 -  HPE Security Fortify on Demand, Ryan Black

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion 

using System;

namespace FoDUploader.API
{
    class ReleaseResponse
    {
        public Release data { get; set; }
        public int responseCode { get; set; }

    }
    class Release
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
