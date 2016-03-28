using System;
using System.IO;
using System.Reflection;
using CommandLine;
using Ionic.Zip;

namespace FoDUploader
{
    class Program
    {
        static bool isTokenAuth = true;
        static long MAXUPLOADSIZEINMB = 5000;
        static string outputName = "fodupload-" + Guid.NewGuid().ToString(); //for the ZIP and log file names

        private static bool isConsole;

        static void Main(string[] args)
        {
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
                    Console.WriteLine(options.GetUsage());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.Message);
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
                    Console.WriteLine("Error authenticating to Fortify on Demand, please check your settings.");
                    Environment.Exit(1);
                }

                Console.WriteLine("Successfully authenticated to Fortify on Demand.");
            }

            FileInfo fi = new FileInfo(zipPath);
            double mbyteSize = (fi.Length / 1024f) / 1024f;
            double kbyteSize = (fi.Length / 1024f);

            if (fi.Length < (1024f * 1024f))
            {
                Console.WriteLine("Payload prepared size: {0}{1}", Math.Round(kbyteSize, 2), " kb");
            }
            else
            {
                Console.WriteLine("Payload prepared size: {0}{1}", Math.Round(mbyteSize, 2), " Mb");
            }          

            if (mbyteSize > MAXUPLOADSIZEINMB)
            {
                Console.WriteLine("Assessment payload size exceeds {0} Mb, cannot continue.", MAXUPLOADSIZEINMB);
                Environment.Exit(1);
            }

            // Ensure a scan is not already running for the application prior to attempting to upload.
            var releaseInfo = api.GetReleaseInfo();

            if(releaseInfo.data.staticScanStatusId == 1 || releaseInfo.data.staticScanStatusId == 4) // "In Progress" or "Waiting"
            {
                Console.WriteLine("Error submitting to Fortify on Demand: You cannot create another scan for \"{0} - {1}\" at this time.", releaseInfo.data.applicationName, releaseInfo.data.releaseName);
                Environment.Exit(1);
        //      Console.ReadKey();
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

            Console.WriteLine("Fortify on Demand Uploader" + Environment.NewLine);
            Console.WriteLine("Selected options: ");
            if (isTokenAuth)
            {
                Console.WriteLine("Using token-based authentication, token: {0}", options.apiToken);
            }
            else
            {
                Console.WriteLine("Using user-based authentication.");
            }
            Console.WriteLine("Automated Audit: {0}", options.automatedAudit ? "Requested" : "Not Requested");
            Console.WriteLine("Express Scan: {0}", options.expressScan ? "Requested" : "Not Requested");
            Console.WriteLine("Sonatype Report: {0}", options.sonatypeReport ? "Requested" : "Not Requested");
     //     Console.WriteLine("Scan BSI URL: {0}", "\"" + options.uploadURL + "\"");
            Console.WriteLine("Assessment payload: {0}", "\"" + options.source + "\"");
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
                    zip.Save();
                    Console.WriteLine("Created ZIP: {0}", zip.Name);
                    zipPath = tempZipPath;
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
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

