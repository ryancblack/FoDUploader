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
        private static string _assessmentTypeId;

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
            var queryParameters = GetqueryParameters(new UriBuilder(options.UploadUrl));
            _technologyStack = queryParameters.Get("ts");
            _languageLevel = queryParameters.Get("ll");
            _tenantCode = queryParameters.Get("tc");
            _assessmentTypeId = queryParameters.Get("astid");

            _includeAllFiles = options.IncludeAllPayload;

            if ((string.IsNullOrEmpty(options.ApiToken) || string.IsNullOrEmpty(options.ApiTokenSecret)))
            {
                if (string.IsNullOrEmpty(options.Username) || string.IsNullOrEmpty(options.Password))
                {
                    Trace.WriteLine("Error: You must specify either an API token and secret or a username and password to authenticate." + Environment.NewLine);
                    Trace.WriteLine(options.GetUsage());
                    Environment.Exit(-1);
                }

                _isTokenAuth = false;
            }

            PrintSelectedOptions(options);

            var zipPath = "";

            // If the user has selected to view entitlement information display it and exit

            if (options.DisplayAccountInformation)
            {
                DisplayAccountInformation(options, zipPath);

                Trace.WriteLine("Note: You may specify an entitlement ID manually with --entitlementID <ID>, please run the utility without --displayEntitlement to proceed.");

                if (_isConsole)
                {
                    Trace.WriteLine("Press any key to quit...");
                    Console.ReadKey();
                    Environment.Exit(0);
                }
                Environment.Exit(0);
            }

            if (string.IsNullOrEmpty(options.Source))
            {
                Trace.WriteLine("Error: You must specify a source folder or ZIP file.");
                Environment.Exit(-1);
            }

            zipPath = ZipFolder(options.Source);

            var api = new FoDapi(options, zipPath, GetqueryParameters(new UriBuilder(options.UploadUrl)));

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


            CheckReleaseStatus(api);

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
        /// Lists all valid assessment types, with entitlement IDs, for Static submissions
        /// </summary>
        /// <param name="options"></param>
        /// <param name="zipPath"></param>
        private static void DisplayAccountInformation(Options options, string zipPath)
        {
            var api = new FoDapi(options, GetqueryParameters(new UriBuilder(options.UploadUrl)));

            if (!api.IsLoggedIn())
            {
                if (!api.Authorize())
                {
                    Trace.WriteLine("Error authenticating to Fortify on Demand, please check your settings.");
                    Environment.Exit(-1);
                }

                Trace.WriteLine("Successfully authenticated to Fortify on Demand.");
            }

            // Once logged in check and display entitlement information related to the release ID.

            api.ListAssessmentTypes();
        }

        /// <summary>
        ///  Checks the release to determine if it's retired, in progress, or paused
        /// </summary>
        /// <param name="api"></param>
        private static void CheckReleaseStatus(FoDapi api)
        {
            var releaseInfo = api.GetReleaseInfo();
            var isRetired = releaseInfo.sdlcStatusType.Equals("Retired");

            if (isRetired) // cannot submit to this release as it is retired in the portal
            {
                Trace.WriteLine($"Error submitting to Fortify on Demand: You cannot create an assessment for \"{releaseInfo.applicationName} - {releaseInfo.releaseName}\" as this release is retired.");
                Environment.Exit(-1);
            }

            // Ensure a scan is not already running for the application prior to attempting to upload.

            if (releaseInfo.currentAnalysisStatusType.Equals("In_Progress") || releaseInfo.currentAnalysisStatusType.Equals("Waiting")) // "In Progress" or "Waiting" // need to checkt these values to see what they map to now
            {
                Trace.WriteLine($"Error submitting to Fortify on Demand: You cannot create another scan for \"{releaseInfo.applicationName} - {releaseInfo.releaseName}\" at this time.");
                Environment.Exit(-1);
            }
        }

        /// <summary>
        ///  Checks if selected optional scan settings may be used and sets entitlement ID to available if not manually specified
        /// </summary>
        /// <param name="api"></param>
        /// <param name="options"></param>
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

        private static void PrintSelectedOptions(Options options)
        {

            Trace.WriteLine(options.AppName);
            Trace.WriteLine(options.Copyright + Environment.NewLine);
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
            Trace.WriteLine($"Entitlement ID: {(options.EntitlementId == null ? "Auto Select" : options.EntitlementId.ToString())}");
            Trace.WriteLine($"Assessment payload: {options.Source}");
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
        private static string ZipFolder(string zipPath, string tempPath = "")
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

                    using (var zip = new ZipFile(zipPath))
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

                    var assessmentFiles = files.Select(fi => fi.FullName).ToList();

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

        private static void ConfigureConsoleOutput()
        {
            try
            {
                // ReSharper disable once UnusedVariable
                var windowHeight = Console.WindowHeight;
                _isConsole = true;
            }
            catch {

                _isConsole = false;

                var streamwriter = new StreamWriter(Console.OpenStandardOutput()) {AutoFlush = true};

                Console.SetOut(streamwriter);
            }
        }
        private static NameValueCollection GetqueryParameters(UriBuilder postUrl)
        {
            var queryParameters = HttpUtility.ParseQueryString(postUrl.Query);
            return queryParameters;
        }
    }
}

