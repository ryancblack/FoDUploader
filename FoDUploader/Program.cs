#region copyright
// Copyright (c) 2016 -  HPE Security Fortify on Demand, Ryan Black

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion 

using System;
using System.IO;
using CommandLine;
using Ionic.Zip;
using System.Diagnostics;
using System.Collections.Specialized;
using System.Web;
using System.Linq;
using System.Collections.Generic;
using System.Text;
using FoDUploader.API;

namespace FoDUploader
{
    class Program
    {
        private static bool isTokenAuth = true;
        private static bool includeAllFiles = false;
        private const long MaxUploadSizeInMB = 5000;
        private static string outputName = "fodupload-" + Guid.NewGuid().ToString(); //for the ZIP and log file names
        private static string logName = Path.Combine(Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.User), outputName + "-log.txt");
        private static string technologyStack = "";
        private static string languageLevel = "";
        private static string tenantCode = "";
        private static int assessmentTypeID;
        private static string[] supportedExtensions = { ".java", ".rb", ".jsp", ".jspx", ".tag", ".tagx", ".tld", ".sql", ".cfm", ".php", ".phtml", ".ctp", ".pks", ".pkh", ".pkb", ".xml", ".config", ".settings", ".properties", ".dll", ".exe", ".inc", ".asp", ".vbscript", ".js", ".ini", ".bas", ".cls", ".vbs", ".frm", ".ctl", ".html", ".htm", ".xsd", ".wsdd", ".xmi", ".py", ".cfml", ".cfc", ".abap", ".xhtml", ".cpx", ".xcfg", ".jsff", ".as", ".mxml", ".cbl", ".cscfg", ".csdef", ".wadcfg", ".appxmanifest", ".wsdl", ".plist", ".bsp", ".abap", ".sln", ".csproj", ".cs", ".pdb", ".war",".ear", ".jar", ".class", ".aspx", ".apk", ".swift" };

        private static bool isConsole;


        static void Main(string[] args)
        {
            try
            {
                Trace.Listeners.Clear();
                TextWriterTraceListener twtl = new TextWriterTraceListener(logName);
                twtl.Name = "Logger";
                twtl.TraceOutputOptions = TraceOptions.ThreadId | TraceOptions.DateTime;
                ConsoleTraceListener ctl = new ConsoleTraceListener(false);
                ctl.TraceOutputOptions = TraceOptions.DateTime;

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
                if(isConsole)
                {
                    Console.ReadKey();
                }
                Environment.Exit(-1);
            }
            
            Environment.Exit(0);
        }

        public static void Run(Options options)
        {
            SetAdditionalOptions(options);
            PrintOptions(options);

            string zipPath = ZipFolder(options.source);

            FoDAPI api = new FoDAPI(options, zipPath);

            if (!api.isLoggedIn())
            {
                if (!api.Authorize())
                {
                    Trace.WriteLine("Error authenticating to Fortify on Demand, please check your settings.");
                    Environment.Exit(1);
                }

                Trace.WriteLine("Successfully authenticated to Fortify on Demand.");
            }

            FileInfo fi = new FileInfo(zipPath);
            double mbyteSize = (fi.Length / 1024f) / 1024f;
            double kbyteSize = (fi.Length / 1024f);

            if (fi.Length < (1024f * 1024f))
            {
                Trace.WriteLine(string.Format("Payload prepared size: {0}{1}", Math.Round(kbyteSize, 2), " kb"));
            }
            else
            {
                Trace.WriteLine(string.Format("Payload prepared size: {0}{1}", Math.Round(mbyteSize, 2), " Mb"));
            }

            if (mbyteSize > MaxUploadSizeInMB)
            {
                Trace.WriteLine(string.Format("Assessment payload size exceeds {0} Mb, cannot continue.", MaxUploadSizeInMB));
                Environment.Exit(1);
            }

            CheckTenantAccountStatus(api, options);

            api.SendScanPost();

            // always retire the token
            api.RetireToken();

            // hold console open
            if (isConsole)
            {
                Console.ReadKey();
            }
        }

        /// <summary>
        /// Checks the existing application to ensure it's not running, paused, and that the tenant account has the required valid entitlement(s) to submit assessments
        /// </summary>
        /// <param name="api"></param>
        private static void CheckTenantAccountStatus(FoDAPI api, Options options)
        {
            var releaseInfo = api.GetReleaseInfo();
            var entitlementInfo = api.GetEntitlementInfo();
            bool isSubscriptionModel = entitlementInfo.data.entitlementTypeId.Equals(1);
            List<TenantEntitlement> returnedEntitlements;
            List<TenantEntitlement> validEntitlements = new List<TenantEntitlement>();

            if (!entitlementInfo.data.tenantEntitlements.Any())
            {
                Trace.WriteLine(string.Format("Error submitting to Fortify on Demand: You have no valid assessment entitlements. Please contact your Technical Account Manager"));
                Environment.Exit(1);
            }

            if (!isSubscriptionModel) // for unit-based entitlement we need to check that assesssmentTypeId has entitlement for the ID specified in the BSI URL the user is trying to use
            {
                returnedEntitlements = entitlementInfo.data.tenantEntitlements.Where(x => x.assessmentTypeId.Equals(assessmentTypeID)).ToList();
            }
            else
            {
                returnedEntitlements = entitlementInfo.data.tenantEntitlements.Where(x => x.assessmentTypeId.Equals(0)).ToList();
            }

            foreach (TenantEntitlement entitlementResult in returnedEntitlements)
            {
                if (DateTime.Now < entitlementResult.endDate)
                {
                    if (entitlementResult.unitsConsumed < entitlementResult.unitsPurchased)
                    {
                        validEntitlements.Add(entitlementResult);
                    }
                }
            }

            if (!validEntitlements.Any())
            {
                Trace.WriteLine(string.Format("Error submitting to Fortify on Demand: You have no valid assessment entitlements for this submission type. Please contact your Technical Account Manager"));
                Environment.Exit(1);
            }

            // Ensure a scan is not already running for the application prior to attempting to upload.

            if (releaseInfo.data.staticScanStatusId == 1 || releaseInfo.data.staticScanStatusId == 4) // "In Progress" or "Waiting"
            {
                Trace.WriteLine(string.Format("Error submitting to Fortify on Demand: You cannot create another scan for \"{0} - {1}\" at this time.", releaseInfo.data.applicationName, releaseInfo.data.releaseName));
                Environment.Exit(1);
            }   
            
            if (options.debug)
            {
                Trace.WriteLine(" ");
                Trace.WriteLine(string.Format("DEBUG: Valid entitlements for: \"{0}\" ", tenantCode));
                foreach (TenantEntitlement entitlement in validEntitlements)
                {
                    Trace.WriteLine("Entitlement ID: " + entitlement.entitlementId.ToString());
                    Trace.WriteLine("Valid For Assesment Type: " + ((entitlement.assessmentTypeId.Equals(0)) ? "Any" : entitlement.assessmentTypeId.ToString()));
                    Trace.WriteLine("Start Date ID: " + entitlement.startDate.ToShortDateString());
                    Trace.WriteLine("End Date ID: " + entitlement.endDate.ToShortDateString());
                    Trace.WriteLine("Units Purchased: " + entitlement.unitsPurchased.ToString());
                    Trace.WriteLine("Units Consumed: " + entitlement.unitsConsumed.ToString());
                    Trace.WriteLine(" ");
                }
            }

            Console.WriteLine("");     
        }

        private static void PrintOptions(Options options)
        {

            Trace.WriteLine(options.appName + Environment.NewLine);
            Trace.WriteLine("Selected options: ");
            if (isTokenAuth)
            {
                Trace.WriteLine(string.Format("Using token-based authentication, token: {0}", options.apiToken));
            }
            else
            {
                Trace.WriteLine("Using user-based authentication.");
            }
            Trace.WriteLine(string.Format("Language Setting: {0} {1}", technologyStack, languageLevel));
            Trace.WriteLine(string.Format("Automated Audit: {0}", options.automatedAudit ? "Requested" : "Not Requested"));
            Trace.WriteLine(string.Format("Express Scan: {0}", options.expressScan ? "Requested" : "Not Requested"));
            Trace.WriteLine(string.Format("Open-source Report: {0}", options.opensourceReport ? "Requested" : "Not Requested"));
            Trace.WriteLine(string.Format("Include Third-Party Libraries: {0}", options.includeThirdParty ? "True" : "False"));
            Trace.WriteLine(string.Format("Assessment payload: {0}", "\"" + options.source + "\""));
            Trace.WriteLine(string.Format("Log file: {0}", "\"" + logName + "\""));

            if (options.debug)
            {
                StringBuilder extensions = new StringBuilder();
                var last = supportedExtensions.Last();

                foreach (string s in supportedExtensions)
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
                Trace.WriteLine(string.Format("Packaged file extensions: {0}", extensions.ToString()));
            }
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
                FileAttributes fa = File.GetAttributes(zipPath);

                if (!fa.HasFlag(FileAttributes.Directory) && Path.GetExtension(zipPath) == ".zip")
                {
                    Trace.WriteLine("Using existing ZIP file.");

                    if(includeAllFiles)
                    {
                        return zipPath;
                    }

                    // decompress to temp location and set zipPath to new folder

                    using (ZipFile zip = new ZipFile(zipPath))
                    {
                        zip.ExtractAll(Path.Combine(Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.User), outputName), ExtractExistingFileAction.OverwriteSilently);
                        zipPath = Path.Combine(Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.User), outputName);
                    }
                }

                if (string.IsNullOrEmpty(tempPath))
                {
                    tempPath = Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.User);
                }

                string tempZipPath = Path.Combine(tempPath, outputName + ".zip");

                if (includeAllFiles || technologyStack.ToUpper() =="OBJECTIVE-C" || technologyStack.ToUpper() =="SWIFT" || technologyStack.ToUpper() == "IOS") //may introduce "iOS" or "SWIFT" - ensure both are handled
                {
                    using (var zip = new ZipFile(tempZipPath))
                    {
                        Trace.WriteLine("Compressing folder without filtering...");
                        zip.AddDirectory(zipPath);
                        if (zip.Entries.Count == 0)
                        {
                            Trace.WriteLine(string.Format("Error: Selected path \"{0}\" contains no files to ZIP. Please check your settings and try again.", zipPath));
                            Environment.Exit(1);
                        }
                        zip.Save();
                        Trace.WriteLine(string.Format("Created ZIP: {0}", zip.Name));
                        zipPath = tempZipPath;
                        return zipPath;
                    } 
                }
                // process supported extensions into ZIP, set zipPath to new ZIP, provide log output

                using (var zip = new ZipFile(tempZipPath))
                {
                    var directory = new DirectoryInfo(zipPath);
                    var files = directory.EnumerateFiles("*", SearchOption.AllDirectories).Where(x => supportedExtensions.Contains(x.Extension.ToLower())).ToList();

                    List<string> assessmentFiles = new List<string>();

                    foreach (FileInfo fi in files)
                    {
                        assessmentFiles.Add(fi.FullName);
                    }

                    Trace.WriteLine("Compressing folder filtered by supported file extensions..");
                    zip.AddFiles(assessmentFiles, true, "");
                    if (zip.Entries.Count == 0)
                    {
                        Trace.WriteLine(string.Format("Error: Selected path \"{0}\" contains no scannable files to ZIP. Please check your application folder and try again.", zipPath));
                        Environment.Exit(1);
                    }
                    zip.Save();
                    Trace.WriteLine(string.Format("Created ZIP: {0}", zip.Name));

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
            NameValueCollection queryParameters = GetqueryParameters(new UriBuilder(options.uploadURL));
            technologyStack = queryParameters.Get("ts");
            languageLevel = queryParameters.Get("ll");
            tenantCode = queryParameters.Get("tc");
            assessmentTypeID = Convert.ToInt32(queryParameters.Get("astid"));

            includeAllFiles = options.includeAllPayload;

            if (string.IsNullOrEmpty(options.apiToken))
            {
                isTokenAuth = false;
            }
        }
        private static void ConfigureConsoleOutput()
        {
            try
            {
                int window_height = Console.WindowHeight;
                isConsole = true;
            }
            catch {

                isConsole = false;

                var streamwriter = new StreamWriter(Console.OpenStandardOutput());

                streamwriter.AutoFlush = true;
                Console.SetOut(streamwriter);
            }
        }
        public static NameValueCollection GetqueryParameters(UriBuilder postURL)
        {
            NameValueCollection queryParameters = HttpUtility.ParseQueryString(postURL.Query);
            return queryParameters;
        }
    }
}

