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
        public string appName = "FoD Uploader 1.03";
        public string copyright = "HPE Security Fortify on Demand, Ryan Black";

        public string GetUsage()
        {
            var help = new HelpText
            {
                Heading = new HeadingInfo(appName),
                Copyright = new CopyrightInfo(copyright, 2016),
                AdditionalNewLineAfterOption = true,
                AddDashesToOption = true
            };

            help.AddPreOptionsLine("");
            help.AddPostOptionsLine("Usage: foduploader.exe --optionName \"Value\"");
            help.AddOptions(this);

            return help;

        }

        [Option("source", Required = true, HelpText = "The ZIP file, or directory to be zipped, for submission to Fortify on Demand.")]
        public string source { get; set; }

        [Option("username", HelpText = "Your portal username.", MutuallyExclusiveSet = "userauth")]
        public string username { get; set; }

        [Option("password", HelpText = "Your portal password.", MutuallyExclusiveSet = "userauth")]
        public string password { get; set; }

        [Option("apiToken", HelpText = "Your api token.", MutuallyExclusiveSet = "tokenauth")]
        public string apiToken { get; set; }

        [Option("apiTokenSecret", HelpText = "Your api token secret key.", MutuallyExclusiveSet = "tokenauth")]
        public string apiTokenSecret { get; set; }

        [Option("uploadURL", Required = true, HelpText = "Your BSI URL for the target application, obtained in the customer portal.")]
        public string uploadURL { get; set; }

        [Option("opensourceReport", DefaultValue = false, HelpText = "If set to true, and enabled in the tenant, an open-source report will be requested.")]
        public bool opensourceReport { get; set; }

        [Option("automatedAudit", DefaultValue = false, HelpText = "If set to true, and enabled in the tenant, the Automated Audit feature will be requested.")]
        public bool automatedAudit { get; set; }

        [Option("expressScan", DefaultValue = false, HelpText = "If set to true, and enabled in the tenant, the Express Scan feature will be requested.")]
        public bool expressScan { get; set; }

        [Option("includeThirdParty", DefaultValue = false, HelpText = "If set to true third-party libraries will be included in assessment results.")]
        public bool includeThirdParty { get; set; }

        [Option("includeAllFiles", DefaultValue = false, HelpText = "If set to true all files, including extraneous non-scannable content, will be submitted to Fortify on Demand. The default of \"false\" will greatly reduce the size of the submission with no impact to assessment quality.")]
        public bool includeAllPayload { get; set; }

        [Option("debug", DefaultValue = false, HelpText = "Verbose setting, API call, POST detail, and entitlement information will be written to the console.")]
        public bool debug { get; set; }
    }
}
