#region copyright
// Copyright (c) 2016 -  HPE Security Fortify on Demand, Ryan Black

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion

using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Web;
using CommandLine;
using FoDUploader.API;
using Ionic.Zip;

namespace FoDUploader
{
    internal static class Program
    {
        private static bool _isTokenAuth = true;
        private static bool _includeAllFiles;
        private const long MaxUploadSizeInMb = 5000;
        private static readonly string OutputName = "fodupload-" + Guid.NewGuid(); //for the ZIP and log file names
        private static readonly string LogName = Path.Combine(Path.GetTempPath(), OutputName + "-log.txt");
        private static string _technologyStack = "";
        private static string _languageLevel = "";
        private static string _tenantCode = "";
        private static int _assessmentTypeId;
        private static readonly string[] SupportedExtensions = { ".java", ".rb", ".jsp", ".jspx", ".tag", ".tagx", ".tld", ".sql", ".cfm", ".php", ".phtml", ".ctp", ".pks", ".pkh", ".pkb", ".xml", ".config", ".settings", ".properties", ".dll", ".exe", ".inc", ".asp", ".vbscript", ".js", ".ini", ".bas", ".cls", ".vbs", ".frm", ".ctl", ".html", ".htm", ".xsd", ".wsdd", ".xmi", ".py", ".cfml", ".cfc", ".abap", ".xhtml", ".cpx", ".xcfg", ".jsff", ".as", ".mxml", ".cbl", ".cscfg", ".csdef", ".wadcfg", ".appxmanifest", ".wsdl", ".plist", ".bsp", ".abap", ".sln", ".csproj", ".cs", ".pdb", ".war",".ear", ".jar", ".class", ".aspx", ".apk", ".swift" };

        private static bool _isConsole;


        private static void Main(string[] args)
        {
            try
            {
                Trace.Listeners.Clear();

                var twtl = new TextWriterTraceListener(LogName)
                {
                    Name = "Logger",
                    TraceOutputOptions = TraceOptions.ThreadId | TraceOptions.DateTime
                };

                var ctl = new ConsoleTraceListener(false) {TraceOutputOptions = TraceOptions.DateTime};

                Trace.Listeners.Add(twtl);
                Trace.Listeners.Add(ctl);
                Trace.AutoFlush = true;
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw;
            }

            var options = new Options();

            ConfigureConsoleOutput();  // detects if app is running in a console, or not (like with TFS), will send all output to stdout for Visual Studio

            try
            {
                if (Parser.Default.ParseArguments(args, options))
                {
                    Run(options);
                }
                else
                {
                    Trace.WriteLine(options.GetUsage());
                    Environment.Exit(-1);
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex.Message);
                if(_isConsole)
                {
                    Console.ReadKey();
                }
                Environment.Exit(-1);
            }
            
            Environment.Exit(0);
        }

        private static void Run(Options options)
        {
            SetAdditionalOptions(options);
            PrintOptions(options);

            var zipPath = ZipFolder(options.Source);

            var api = new FoDapi(options, zipPath);

            if (!api.IsLoggedIn())
            {
                if (!api.Authorize())
                {
                    Trace.WriteLine("Error authenticating to Fortify on Demand, please check your settings.");
                    Environment.Exit(-1);
                }

                Trace.WriteLine("Successfully authenticated to Fortify on Demand.");
            }

            var fi = new FileInfo(zipPath);

            double mbyteSize = (fi.Length / 1024f) / 1024f;
            double kbyteSize = (fi.Length / 1024f);

            Trace.WriteLine(fi.Length < (1024f*1024f)
                ? $"Payload prepared size: {Math.Round(kbyteSize, 2)} kb"
                : $"Payload prepared size: {Math.Round(mbyteSize, 2)} Mb");

            if (mbyteSize > MaxUploadSizeInMb)
            {
                Trace.WriteLine($"Assessment payload size exceeds {MaxUploadSizeInMb} Mb, cannot continue.");
                Environment.Exit(-1);
            }

            /*
             * 
            API tokens with "start scans" only privileges cannot access entitlement information, we'll have to rely on the API response error from attempting to post to know if we can submit an assessment

            - First, determine if the provided authentication information can see entitlement info and, if so, check it, if not continue and rely on the API response
            - Second, determine if the release is retired, in progress, or paused - any of these would prevent another submission

            The reason for all this is to save a potentially-significant amount of time waiting on an upload, if possible, only to find by the response that we cannot proceed or that there was simply "an error" - normally caused by one of these testable conditions.

            */

            CheckReleaseStatus(api);

            CheckEntitlementStatus(api, options);

            CheckAssessmentOptions(api, options);

            api.SendScanPost();

            // always retire the token

            api.RetireToken();

            // hold console open - ask around if this is something we want to do for interactive runs? Feedback has been conflicting regarding this behavior.

            if (_isConsole)
            {
                Console.ReadKey();
            }
        }

        /// <summary>
        ///  Checks the release to determine if it's retired, in progress, or paused
        /// </summary>
        /// <param name="api"></param>
        private static void CheckReleaseStatus(FoDapi api)
        {
            var releaseInfo = api.GetReleaseInfo();
            var isRetired = releaseInfo.Data.StaticScanStatusId.Equals(0);

            if (isRetired) // cannot submit to this release as it is retired in the portal
            {
                Trace.WriteLine($"Error submitting to Fortify on Demand: You cannot create an assessment for \"{releaseInfo.Data.ApplicationName} - {releaseInfo.Data.ReleaseName}\" as this release is retired.");
                Environment.Exit(-1);
            }

            // Ensure a scan is not already running for the application prior to attempting to upload.

            if (releaseInfo.Data.StaticScanStatusId == 1 || releaseInfo.Data.StaticScanStatusId == 4) // "In Progress" or "Waiting"
            {
                Trace.WriteLine($"Error submitting to Fortify on Demand: You cannot create another scan for \"{releaseInfo.Data.ApplicationName} - {releaseInfo.Data.ReleaseName}\" at this time.");
                Environment.Exit(-1);
            }
        }

        /// <summary>
        ///  Checks the entitlement status of the tenant account. If entitlement information cannot be read it will log this and allow a scan upload attempt to continue. 
        ///  "Start scan" API tokens cannot read entitlement information
        /// </summary>
        /// <param name="api"></param>
        /// <param name="options"></param>
        private static void CheckEntitlementStatus(FoDapi api, Options options)
        {
            var entitlementInfo = api.GetEntitlementInfo();

            if (entitlementInfo.Data != null) // will be null if we're unable to read this with an under-privileged token, in this case it'll be logged in the call
            {
                bool isSubscriptionModel = entitlementInfo.Data.EntitlementTypeId.Equals(1);
                List<TenantEntitlement> returnedEntitlements;
                List<TenantEntitlement> validEntitlements = new List<TenantEntitlement>();

                if (!entitlementInfo.Data.TenantEntitlements.Any())
                {
                    Trace.WriteLine("Error submitting to Fortify on Demand: You have no valid assessment entitlements. Please contact your Technical Account Manager");
                    Environment.Exit(-1);
                }

                // ReSharper disable once ConvertIfStatementToConditionalTernaryExpression
                if (!isSubscriptionModel) // for unit-based entitlement we need to check that assesssmentTypeId has entitlement for the ID specified in the BSI URL the user is trying to use
                {
                    returnedEntitlements = entitlementInfo.Data.TenantEntitlements.Where(x => x.AssessmentTypeId.Equals(_assessmentTypeId)).ToList();
                }
                else
                {
                    returnedEntitlements = entitlementInfo.Data.TenantEntitlements.Where(x => x.AssessmentTypeId.Equals(0)).ToList();
                }

                // ReSharper disable once LoopCanBeConvertedToQuery
                foreach (var entitlementResult in returnedEntitlements)
                {
                    if (DateTime.Now >= entitlementResult.EndDate) continue;
                    if (entitlementResult.UnitsConsumed < entitlementResult.UnitsPurchased)
                    {
                        validEntitlements.Add(entitlementResult);
                    }
                }

                if (!validEntitlements.Any())
                {
                    Trace.WriteLine("Error submitting to Fortify on Demand: You have no valid assessment entitlements for this submission type. Please contact your Technical Account Manager");
                    Environment.Exit(-1);
                }

                if (options.Debug)
                {
                    Trace.WriteLine(" ");
                    Trace.WriteLine($"DEBUG: Valid entitlements for: \"{_tenantCode}\" ");
                    foreach (var entitlement in validEntitlements)
                    {
                        Trace.WriteLine("Entitlement ID: " + entitlement.EntitlementId);
                        Trace.WriteLine("Valid For Assesment Type: " + ((entitlement.AssessmentTypeId.Equals(0)) ? "Any" : entitlement.AssessmentTypeId.ToString()));
                        Trace.WriteLine("Start Date ID: " + entitlement.StartDate.ToShortDateString());
                        Trace.WriteLine("End Date ID: " + entitlement.EndDate.ToShortDateString());
                        Trace.WriteLine("Units Purchased: " + entitlement.UnitsPurchased);
                        Trace.WriteLine("Units Consumed: " + entitlement.UnitsConsumed);
                        Trace.WriteLine(" ");
                    }
                }

                Console.WriteLine("");
            }

        }

        private static void CheckAssessmentOptions(FoDapi api, Options options)
        {
            var assessmentFeatures = api.GetFeatureInfo();
            var features = assessmentFeatures.Items.Select(feature => feature.Name).ToList();

            if (options.OpensourceReport)
            {
                if (!features.Contains("SonaType"))
                {
                    Trace.WriteLine("Note: Open-source reporting is not enabled for your account, proceeding without this option.");
                }
            }
            if (options.AutomatedAudit)
            {
                if (!features.Contains("AuditPreference"))
                {
                    Trace.WriteLine("Note: Automated Audit is not enabled for your account, proceeding without this option.");
                }
            }
            if (options.ExpressScan)
            {
                if (!features.Contains("ScanPreference"))
                {
                    Trace.WriteLine("Note: Express Scan is not enabled for your account, proceeding without this option.");
                }
            }

        }

        private static void PrintOptions(Options options)
        {

            Trace.WriteLine(options.AppName + Environment.NewLine);
            Trace.WriteLine("Selected options: ");
            // ReSharper disable once ConvertIfStatementToConditionalTernaryExpression
            if (_isTokenAuth)
            {
                Trace.WriteLine($"Using token-based authentication, token: {options.ApiToken}");
            }
            else
            {
                Trace.WriteLine("Using user-based authentication.");
            }
            Trace.WriteLine($"Language Setting: {_technologyStack} {_languageLevel}");
            Trace.WriteLine($"Automated Audit: {(options.AutomatedAudit ? "Requested" : "Not Requested")}");
            Trace.WriteLine($"Express Scan: {(options.ExpressScan ? "Requested" : "Not Requested")}");
            Trace.WriteLine($"Open-source Report: {(options.OpensourceReport ? "Requested" : "Not Requested")}");
            Trace.WriteLine($"Include Third-Party Libraries: {(options.IncludeThirdParty ? "True" : "False")}");
            Trace.WriteLine($"Assessment payload: {"\"" + options.Source + "\""}");
            Trace.WriteLine($"Log file: {"\"" + LogName + "\""}");

            if (!options.Debug) return;
            var extensions = new StringBuilder();
            var last = SupportedExtensions.Last();

            foreach (var s in SupportedExtensions)
            {
                if (s.Equals(last))
                {
                    extensions.Append(s);
                }
                else
                {
                    extensions.Append(s + ", ");
                }
            }
            Trace.WriteLine($"Packaged file extensions: {extensions}");
        }

        /// <summary>
        /// Checks of path is already zipped if it is it submits as-is, if not, it zips the folder and all contents to a zip file appending a guid to the name,
        /// places in the tempPath provided
        /// </summary>
        /// <param name="zipPath">Folder to be zipped</param>
        /// <param name="tempPath">Optional output path for the zipped file, defaults to Windows temp</param>
        /// <returns>Path to the zip file</returns>
        public static string ZipFolder(string zipPath, string tempPath = "")
        {
            try
            {
                var fa = File.GetAttributes(zipPath);

                if (!fa.HasFlag(FileAttributes.Directory) && Path.GetExtension(zipPath) == ".zip")
                {
                    Trace.WriteLine("Using existing ZIP file.");

                    if(_includeAllFiles)
                    {
                        return zipPath;
                    }

                    // decompress to temp location and set zipPath to new folder

                    using (ZipFile zip = new ZipFile(zipPath))
                    {
                        zip.ExtractAll(Path.Combine(Path.GetTempPath(), OutputName), ExtractExistingFileAction.OverwriteSilently);
                        zipPath = Path.Combine(Path.GetTempPath(), OutputName);
                    }
                }

                if (string.IsNullOrEmpty(tempPath))
                {
                    tempPath = Path.GetTempPath();
                }

                var tempZipPath = Path.Combine(tempPath, OutputName + ".zip");

                if (_includeAllFiles || _technologyStack.ToUpper() =="OBJECTIVE-C" || _technologyStack.ToUpper() =="SWIFT" || _technologyStack.ToUpper() == "IOS") //may introduce "iOS" or "SWIFT" - ensure both are handled
                {
                    using (var zip = new ZipFile(tempZipPath))
                    {
                        Trace.WriteLine("Compressing folder without filtering...");
                        zip.AddDirectory(zipPath);
                        if (zip.Entries.Count == 0)
                        {
                            Trace.WriteLine(
                                $"Error: Selected path \"{zipPath}\" contains no files to ZIP. Please check your settings and try again.");
                            Environment.Exit(-1);
                        }
                        zip.Save();
                        Trace.WriteLine($"Created ZIP: {zip.Name}");
                        zipPath = tempZipPath;
                        return zipPath;
                    } 
                }
                // process supported extensions into ZIP, set zipPath to new ZIP, provide log output

                using (var zip = new ZipFile(tempZipPath))
                {
                    var directory = new DirectoryInfo(zipPath);
                    var files = directory.EnumerateFiles("*", SearchOption.AllDirectories).Where(x => SupportedExtensions.Contains(x.Extension.ToLower())).ToList();

                    List<string> assessmentFiles = new List<string>();

                    foreach (var fi in files)
                    {
                        assessmentFiles.Add(fi.FullName);
                    }

                    Trace.WriteLine("Compressing folder filtered by supported file extensions..");
                    zip.AddFiles(assessmentFiles, true, "");
                    if (zip.Entries.Count == 0)
                    {
                        Trace.WriteLine(
                            $"Error: Selected path \"{zipPath}\" contains no scannable files to ZIP. Please check your application folder and try again.");
                        Environment.Exit(-1);
                    }
                    zip.Save();
                    Trace.WriteLine($"Created ZIP: {zip.Name}");

                    return tempZipPath;
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                Environment.Exit(-1);
            }

            return zipPath;
        }

        /// <summary>
        /// Toggles authtoken/user auth, sets language information for ZIP filtering, and preference to include all application content
        /// </summary>
        /// <param name="options">command line options object</param>
        private static void SetAdditionalOptions(Options options)
        {
            NameValueCollection queryParameters = GetqueryParameters(new UriBuilder(options.UploadUrl));
            _technologyStack = queryParameters.Get("ts");
            _languageLevel = queryParameters.Get("ll");
            _tenantCode = queryParameters.Get("tc");
            _assessmentTypeId = Convert.ToInt32(queryParameters.Get("astid"));

            _includeAllFiles = options.IncludeAllPayload;

            if (string.IsNullOrEmpty(options.ApiToken))
            {
                _isTokenAuth = false;
            }
        }
        private static void ConfigureConsoleOutput()
        {
            try
            {
                // ReSharper disable once UnusedVariable
                int windowHeight = Console.WindowHeight;
                _isConsole = true;
            }
            catch {

                _isConsole = false;

                var streamwriter = new StreamWriter(Console.OpenStandardOutput()) {AutoFlush = true};

                Console.SetOut(streamwriter);
            }
        }
        public static NameValueCollection GetqueryParameters(UriBuilder postUrl)
        {
            var queryParameters = HttpUtility.ParseQueryString(postUrl.Query);
            return queryParameters;
        }
    }
}

