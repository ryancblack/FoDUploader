#region copyright
// Copyright (c) 2016 -  HPE Security Fortify on Demand, Ryan Black

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion

using CommandLine;
using CommandLine.Text;

namespace FoDUploader
{
    class Options
    {
        public string AppName = "FoD Uploader 1.05";
        public string Copyright = "HPE Security Fortify on Demand, Ryan Black";

        public string GetUsage()
        {
            var help = new HelpText
            {
                Heading = new HeadingInfo(AppName),
                Copyright = new CopyrightInfo(Copyright, 2016),
                AdditionalNewLineAfterOption = true,
                AddDashesToOption = true
            };

            help.AddPreOptionsLine("");
            help.AddPostOptionsLine("Usage: foduploader.exe --optionName \"Value\"");
            help.AddOptions(this);

            return help;

        }

        [Option("source", HelpText = "The ZIP file, or directory to be zipped, for submission to Fortify on Demand.")]
        public string Source { get; set; }

        [Option("username", HelpText = "Your portal username.", MutuallyExclusiveSet = "userauth")]
        public string Username { get; set; }

        [Option("password", HelpText = "Your portal password.", MutuallyExclusiveSet = "userauth")]
        public string Password { get; set; }

        [Option("apiToken", HelpText = "Your api token.", MutuallyExclusiveSet = "tokenauth")]
        public string ApiToken { get; set; }

        [Option("apiTokenSecret", HelpText = "Your api token secret key.", MutuallyExclusiveSet = "tokenauth")]
        public string ApiTokenSecret { get; set; }

        [Option("uploadURL", Required = true, HelpText = "Your BSI URL for the target application, obtained in the customer portal.")]
        public string UploadUrl { get; set; }

        [Option("opensourceReport", DefaultValue = false, HelpText = "If set to true, and enabled in the tenant, an open-source report will be requested.")]
        public bool OpensourceReport { get; set; }

        [Option("automatedAudit", DefaultValue = false, HelpText = "If set to true, and enabled in the tenant, the Automated Audit feature will be requested.")]
        public bool AutomatedAudit { get; set; }

        [Option("expressScan", DefaultValue = false, HelpText = "If set to true, and enabled in the tenant, the Express Scan feature will be requested.")]
        public bool ExpressScan { get; set; }

        [Option("includeThirdParty", DefaultValue = false, HelpText = "If set to true third-party libraries will be included in assessment results.")]
        public bool IncludeThirdParty { get; set; }

        [Option("includeAllFiles", DefaultValue = false, HelpText = "If set to true all files, including extraneous non-scannable content, will be submitted to Fortify on Demand. The default of \"false\" will greatly reduce the size of the submission with no impact to assessment quality.")]
        public bool IncludeAllPayload { get; set;}

        [Option("displayEntitlement", DefaultValue = false, HelpText = "Displays entitlement information related to the application release ID. This option may be used to determine which specific entitlement is desired for manual specification; if enabled no assessment is submitted.")]
        public bool DisplayAccountInformation { get; set; }

        [Option("entitlementId", HelpText = "Optionally set an entitlement ID to use for the assessment")]
        public int? EntitlementId { get; set; }

        [Option("debug", DefaultValue = false, HelpText = "Verbose setting, API call, POST detail, and entitlement information will be written to the console.")]
        public bool Debug { get; set; }

    }
}
