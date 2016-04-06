using System;
using System.IO;
using CommandLine;
using Ionic.Zip;
using System.Diagnostics;

namespace FoDUploader
{
    class Program
    {
        private static bool isTokenAuth = true;
        private const long MaxUploadSizeInMB = 5000;
        private static string outputName = "fodupload-" + Guid.NewGuid().ToString(); //for the ZIP and log file names

        private static bool isConsole;

        static void Main(string[] args)
        {
            Trace.Listeners.Clear();
            TextWriterTraceListener twtl = new TextWriterTraceListener(Path.Combine(Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.User), outputName + "-log.txt"));
            twtl.Name = "Logger";
            twtl.TraceOutputOptions = TraceOptions.ThreadId | TraceOptions.DateTime;
            ConsoleTraceListener ctl = new ConsoleTraceListener(false);
            ctl.TraceOutputOptions = TraceOptions.DateTime;

            Trace.Listeners.Add(twtl);
            Trace.Listeners.Add(ctl);
            Trace.AutoFlush = true;

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
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex.Message);
                if(isConsole)
                {
                    Console.ReadKey();
                }
            }
        }

        public static void Run(Options options)
        {
            SetAdditionalOptions(options);
            PrintOptions(options);

            string zipPath = ZipFolder(options.source);

            FoDAPI api = new FoDAPI(options, zipPath);

            if (!api.isLoggedIn())
            {
                if(!api.Authorize())
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

            // Ensure a scan is not already running for the application prior to attempting to upload.
            var releaseInfo = api.GetReleaseInfo();

            if(releaseInfo.data.staticScanStatusId == 1 || releaseInfo.data.staticScanStatusId == 4) // "In Progress" or "Waiting"
            {
                Trace.WriteLine(string.Format("Error submitting to Fortify on Demand: You cannot create another scan for \"{0} - {1}\" at this time.", releaseInfo.data.applicationName, releaseInfo.data.releaseName));
                Environment.Exit(1);
             // Console.ReadKey();
            }

            api.SendScanPost();

            // always retire the token
            api.RetireToken();

            // hold console open
            if (isConsole)
            {
                Console.ReadKey();
            }
        }

        private static void PrintOptions(Options options)
        {

            Trace.WriteLine("Fortify on Demand Uploader" + Environment.NewLine);
            Trace.WriteLine("Selected options: ");
            if (isTokenAuth)
            {
                Trace.WriteLine(string.Format("Using token-based authentication, token: {0}", options.apiToken));
            }
            else
            {
                Trace.WriteLine("Using user-based authentication.");
            }
            Trace.WriteLine(string.Format("Automated Audit: {0}", options.automatedAudit ? "Requested" : "Not Requested"));
            Trace.WriteLine(string.Format("Express Scan: {0}", options.expressScan ? "Requested" : "Not Requested"));
            Trace.WriteLine(string.Format("Sonatype Report: {0}", options.sonatypeReport ? "Requested" : "Not Requested"));
            Trace.WriteLine(string.Format("Include Third-Party Libraries: {0}", options.includeThirdParty ? "True" : "False"));
            Trace.WriteLine(string.Format("Assessment payload: {0}", "\"" + options.source + "\""));
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
                    return zipPath;
                }

                if (string.IsNullOrEmpty(tempPath))
                {
                    tempPath = Environment.GetEnvironmentVariable("TEMP", EnvironmentVariableTarget.User);
                }

                string tempZipPath = Path.Combine(tempPath, outputName + ".zip");

                using (var zip = new ZipFile(tempZipPath))
                {
                    zip.AddDirectory(zipPath);
                    if (zip.Entries.Count == 0)
                    {
                        Trace.WriteLine(string.Format("Error: Selected path \"{0}\" contains no files to ZIP. Please check your settings and try again.", zipPath));
                        Environment.Exit(1);
                    }
                    zip.Save();
                    Trace.WriteLine(string.Format("Created ZIP: {0}", zip.Name));
                    zipPath = tempZipPath;
                }
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
            }

            return zipPath;
        }

        /// <summary>
        /// Toggles authtoken/user auth
        /// </summary>
        /// <param name="options">command line options object</param>
        private static void SetAdditionalOptions(Options options)
        {
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
    }
}

