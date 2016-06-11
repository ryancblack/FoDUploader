#region copyright
// Copyright (c) 2016 -  HPE Security Fortify on Demand, Ryan Black

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion 

namespace FoDUploader.API
{
    class Release
    {
        public int releaseId { get; set; }
        public string releaseName { get; set; }
        public string releaseDescription { get; set; }
        public string releaseCreatedDate { get; set; }
        public int applicationId { get; set; }
        public string applicationName { get; set; }
        public int currentAnalysisStatusTypeId { get; set; }
        public string currentAnalysisStatusType { get; set; }
        public int rating { get; set; }
        public int critical { get; set; }
        public int high { get; set; }
        public int medium { get; set; }
        public int low { get; set; }
        public int currentStaticScanId { get; set; }
        public int currentDynamicScanId { get; set; }
        public int currentMobileScanId { get; set; }
        public string staticAnalysisStatusType { get; set; }
        public string dynamicAnalysisStatusType { get; set; }
        public string mobileAnalysisStatusType { get; set; }
        public int staticAnalysisStatusTypeId { get; set; }
        public int dynamicAnalysisStatusTypeId { get; set; }
        public int mobileAnalysisStatusTypeId { get; set; }
        public string staticScanDate { get; set; }
        public string dynamicScanDate { get; set; }
        public string mobileScanDate { get; set; }
        public int issueCount { get; set; }
        public bool isPassed { get; set; }
        public int passFailReasonTypeId { get; set; }
        public string passFailReasonType { get; set; }
        public int sdlcStatusTypeId { get; set; }
        public string sdlcStatusType { get; set; }

    }
}
