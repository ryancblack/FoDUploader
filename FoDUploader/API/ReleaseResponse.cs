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
        public Release Data { get; set; }
        public int ResponseCode { get; set; }

    }
    class Release
    {
        //https://hpfod.com/api/v1/Release/{releaseId}

        public int ApplicationId { get; set; }
        public int ReleaseId { get; set; }
        public string ApplicationName { get; set; }
        public string ReleaseName { get; set; }
        public int Status { get; set; }
        public int Rating { get; set; }
        public int Critical { get; set; }
        public int High { get; set; }
        public int Medium { get; set; }
        public int Low { get; set; }
        public int ScanStatus { get; set; }
        public int CurrentStaticScanId { get; set; }
        public int CurrentDynamicScanId { get; set; }
        public int CurrentMobileScanId { get; set; }
        public string DynamicScanStatus { get; set; }
        public int StaticScanStatus { get; set; }
        public int MobileScanStatus { get; set; }
        public int DynamicScanStatusId { get; set; }
        public int StaticScanStatusId { get; set; }
        public int MobileScanStatusId { get; set; }
        public DateTime DynamicScanDate { get; set; }
        public DateTime StaticScanDate { get; set; }
        public DateTime MobileScanDate { get; set; }
        public int IssueCount { get; set; }
        public bool IsPassed { get; set; }
        public int PassFailReasonId { get; set; }
        public int ReleaseSdlcStatusId { get; set; }
        public string ReleaseSdlcStatusValue { get; set; }
    }
}
