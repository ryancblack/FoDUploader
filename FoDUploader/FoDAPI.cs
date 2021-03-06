﻿#region copyright
// Copyright (c) 2016 -  HPE Security Fortify on Demand, Ryan Black

//Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:

//The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.

//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
#endregion

using System;
using System.Collections.Specialized;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using FoDUploader.API;
using RestSharp;
using RestSharp.Deserializers;
using System.Net;
using System.Web;

namespace FoDUploader
{
    internal class FoDapi
    {
        private readonly string _apiToken;
        private readonly string _apiSecret;
        private readonly string _userName;
        private readonly string _password;
        private readonly string _submissionZip;
        private string _entitlementFrequencyType;
        private int? _entitlementId;

        private readonly bool _doOpensourceReport;
        private readonly bool _doExpressScan;
        private readonly bool _doAutomatedAudit;
        private readonly bool _includeThirdParty;

        private readonly bool _isTokenAuth;
        private readonly bool _isDebug;

        private string _accessToken;

        private readonly UriBuilder _baseUri;
        private readonly NameValueCollection _queryParameters;


        private const long Seglen = (1024 * 1024) * 10;  // 10Mb chunk size
        private const int Globaltimeoutinminutes = 1 * 60000;
        private const int Maxretries = 5;

        #region Constructors
        /// <summary>
        /// Constructor for checking tenant information only
        /// </summary>
        /// <param name="options"></param>
        /// <param name="parameters"></param>
        public FoDapi(Options options, NameValueCollection parameters)
        {
            _baseUri = new UriBuilder(options.UploadUrl);
            _queryParameters = parameters;
            _isTokenAuth = (string.IsNullOrWhiteSpace(options.Username));
            _apiToken = options.ApiToken;
            _apiSecret = options.ApiTokenSecret;
            _userName = options.Username;
            _password = options.Password;
            _doAutomatedAudit = options.AutomatedAudit;
            _doOpensourceReport = options.OpensourceReport;
            _doExpressScan = options.ExpressScan;
            _includeThirdParty = options.IncludeThirdParty;
            _isDebug = options.Debug;
        }

        /// <summary>
        /// Constructor for submitting an assessment
        /// </summary>
        /// <param name="options"></param>
        /// <param name="zip"></param>
        /// <param name="parameters"></param>
        public FoDapi(Options options, string zip, NameValueCollection parameters)
        {
            _baseUri = new UriBuilder(options.UploadUrl);
            _queryParameters = parameters;
            _isTokenAuth = (string.IsNullOrWhiteSpace(options.Username));
            _submissionZip = zip;
            _apiToken = options.ApiToken;
            _apiSecret = options.ApiTokenSecret;
            _userName = options.Username;
            _password = options.Password;
            _entitlementId = options.EntitlementId;
            _doAutomatedAudit = options.AutomatedAudit;
            _doOpensourceReport = options.OpensourceReport;
            _doExpressScan = options.ExpressScan;
            _includeThirdParty = options.IncludeThirdParty;
            _isDebug = options.Debug;
        }

        #endregion

        #region Authentication

        /// <summary>
        /// Obtains, or updates, the authorization token for FoD. If isAuthToken is true client_credentials will be used instead of password
        /// </summary>
        public bool Authorize()
        {
            var sb = new StringBuilder();
            sb.Append(_baseUri.Scheme);
            sb.Append("://");
            sb.Append(_baseUri.Host + "/");
            sb.Append("oauth/token");

            var client = new RestClient(sb.ToString());
            var request = new RestRequest("", Method.POST);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            request.AddParameter("scope", "https://hpfod.com/tenant");

            if (_isTokenAuth)
            {
                request.AddParameter("grant_type", "client_credentials");
                request.AddParameter("client_id", _apiToken);
                request.AddParameter("client_secret", _apiSecret);
            }
            else
            {
                request.AddParameter("grant_type", "password");
                request.AddParameter("username", _queryParameters.Get("tc") + @"\" + _userName);
                request.AddParameter("password", _password);
            }

            var attempts = 0;

            do
            {
                try
                {
                    attempts++;
                    var response = client.Execute(request);
                    _accessToken = new JsonDeserializer().Deserialize<AuthorizationResponse>(response).AccessToken;

                    if (!string.IsNullOrEmpty(_accessToken))
                    {
                        if (_isDebug)
                        {
                            Trace.WriteLine($"DEBUG: Authentication Token: {_accessToken}");
                        }
                        return true;
                    }
                }
                catch (Exception)
                {
                    _accessToken = null;
                    Trace.WriteLine($"Error count {attempts} retrieving API access token");
                }
            }
            while (attempts <= Maxretries);

            return false;
        }

        public void RetireToken()
        {
            var sb = new StringBuilder();
            sb.Append(_baseUri.Scheme);
            sb.Append("://");
            sb.Append(_baseUri.Host + "/");
            sb.Append("oauth/retireToken");

            var client = new RestClient(sb.ToString());
            var request = new RestRequest("", Method.GET);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            request.AddHeader("Auhorization", "Bearer " + _accessToken);

            try
            {
                var response = client.Execute(request);
                _accessToken = new JsonDeserializer().Deserialize<AuthorizationResponse>(response).AccessToken;
            }
            catch (Exception ex)
            {
                _accessToken = null;
                Trace.WriteLine(ex.Message);
                throw;
            }
        }

        public bool IsLoggedIn()
        {
            return !string.IsNullOrWhiteSpace(_accessToken);
        }


        #endregion

        #region Endpoint Calls
        public Release GetReleaseInfo()
        {

            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v3/releases/");
            endpoint.Append(_queryParameters.Get("pv"));

            var client = new RestClient(endpoint.ToString()) { Timeout = Globaltimeoutinminutes * 120 };
            var request = new RestRequest(Method.GET);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            request.AddHeader("Authorization", "Bearer " + _accessToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            try
            {
                var response = client.Execute(request);
                var release = new JsonDeserializer().Deserialize<Release>(response);
                return release;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                throw;
            }
        }

        private AssessmentTypes GetAssessmentTypes()
        {
            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v3/releases/");
            endpoint.Append(_queryParameters.Get("pv"));
            endpoint.Append("/assessment-types");

            var client = new RestClient(endpoint.ToString()) { Timeout = Globaltimeoutinminutes * 120 };
            var request = new RestRequest(Method.GET);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            request.AddQueryParameter("scantype", "static");

            request.AddHeader("Authorization", "Bearer " + _accessToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            try
            {
                var response = client.Execute(request);
                var assessmentTypes = new JsonDeserializer().Deserialize<AssessmentTypes>(response);
                return assessmentTypes;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                throw;
            }
        }

        /// <summary>
        /// Retrieves the optional features on the account, e.g. Sonatype reporting, express scanning, and automated audit
        /// </summary>
        /// <returns>Features object</returns>
        public Features GetFeatureInfo()
        {
            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v3/tenants/features");

            var client = new RestClient(endpoint.ToString()) { Timeout = Globaltimeoutinminutes * 120 };
            var request = new RestRequest(Method.GET);
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            request.AddHeader("Authorization", "Bearer " + _accessToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            try
            {
                var response = client.Execute(request);

                var scanfeatures = new JsonDeserializer().Deserialize<Features>(response);
                return scanfeatures;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                throw;
            }
        }
        #endregion

        #region Data POSTs
        public void SendScanPost()
        {
            // endpoint: POST /api/v3/releases/{releaseId}/static-scans/start-scan
            // required parameters: releaseId, assessmentTypeId, technologyStack, languageLevel, fragNo, offset, entitlementId, entitlementFrequencyType
            // New optional: isRemediationScan*

            SetEntitlementInformation();

            var fi = new FileInfo(_submissionZip);

            Trace.WriteLine("Beginning upload....");

            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v3/releases/");
            endpoint.Append(_queryParameters.Get("pv"));
            endpoint.Append("/static-scans/start-scan");

            var client = new RestClient(endpoint.ToString()) { Timeout = Globaltimeoutinminutes * 120 };
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12;

            // Read it in chunks
            var uploadStatus = "";
            IRestResponse response = null;

            using (var fs = new FileStream(_submissionZip, FileMode.Open))
            {
                byte[] readByteBuffer = new byte[Seglen];

                var fragmentNumber = 0;
                var offset = 0;
                double bytesSent = 0;
                double fileSize = fi.Length;
                var chunkSize = Seglen;

                try
                {
                    int bytesRead;
                    while ((bytesRead = fs.Read(readByteBuffer, 0, (int)chunkSize)) > 0)
                    {
                        var uploadProgress = Math.Round(((decimal)bytesSent / (decimal)fileSize) * 100.0M);

                        var sendByteBuffer = new byte[chunkSize];

                        if (bytesRead < Seglen)
                        {
                            fragmentNumber = -1;
                            Array.Resize(ref sendByteBuffer, bytesRead);
                            Array.Copy(readByteBuffer, sendByteBuffer, sendByteBuffer.Length);
                            response = SendData(client, sendByteBuffer, fragmentNumber, offset);
                            uploadStatus = response.StatusCode.ToString();
                            break;
                        }
                        Array.Copy(readByteBuffer, sendByteBuffer, sendByteBuffer.Length);
                        response = SendData(client, sendByteBuffer, fragmentNumber++, offset);

                        uploadStatus = response.StatusCode.ToString();
                        offset += bytesRead;
                        bytesSent += bytesRead;

                        if ((fs.Length - offset) < Seglen)
                        {
                            chunkSize = (fs.Length - offset);
                        }
                        Trace.WriteLine(uploadProgress + "%");
                    }
                }
                catch (Exception ex)
                {
                    Trace.WriteLine(ex);
                    throw;
                }
                finally
                {
                    // ReSharper disable once ConstantConditionalAccessQualifier
                    fs?.Close();
                }

                if (uploadStatus.Equals("OK"))
                {
                    Trace.WriteLine("Assessment submission successful.");
                }
                else
                {
                    Trace.WriteLine("Status: " + uploadStatus);
                    if (uploadStatus.Equals("BadRequest"))
                    {
                        var errors = new JsonDeserializer().Deserialize<ErrorResponse>(response);
                        foreach (var e in errors.Errors)
                            Trace.WriteLine($"Error: {e.Message}");
                    }
                    else
                    {
                        Trace.WriteLine("Error submitting to Fortify on Demand.");
                    }
                    Environment.Exit(-1);
                }
            }
        }

        private IRestResponse SendData(RestClient client, byte[] data, long fragNo, long offset)
        {
            // endpoint: POST /api/v3/releases/{releaseId}/static-scans/start-scan
            // required parameters: releaseId, assessmentTypeId, technologyStack, languageLevel, fragNo, offset, entitlementId, entitlementFrequencyType
            // New optional: isRemediationScan*
            // *I don't know if we really care about this when wanting to start a scan?

            var request = new RestRequest(Method.POST);

            request.AddHeader("Authorization", "Bearer " + _accessToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            // add assessment-related parameters

            request = AddAssessmentParameters(request);

            request.AddQueryParameter("fragNo", fragNo.ToString());
            request.AddQueryParameter("offset", offset.ToString());
            request.AddParameter("application/octet-stream", data, ParameterType.RequestBody);

            var postUri = client.BuildUri(request).AbsoluteUri;

            if (_isDebug)
            {
                Trace.WriteLine($"DEBUG: POST string: {postUri}");
            }

            var attempts = 0;
            string httpStatus;
            IRestResponse response;

            do
            {
                response = client.Execute(request);
                httpStatus = response.StatusCode.ToString();
                attempts++;
                // We should also break here on BadRequest as the api returns error messages in this case that we can parse.
                if (httpStatus.Equals("Accepted") || httpStatus.Equals("OK") || httpStatus.Equals("BadRequest"))  // the final response for the -1 fragment is OK instead of Accepted
                {
                    break;
                }

                if (_isDebug)
                {
                    Trace.WriteLine("Error: POST Response: " + response.Content);
                }
                if (attempts >= Maxretries)
                {
                    Trace.WriteLine("Error: Maximum POST attempts reached, please check your connection and try again later.");
                    break;
                }
            }

            while (httpStatus != "OK" || attempts < Maxretries);

            return response;
        }
        #endregion

        #region Utility Methods
        /// <summary>
        ///  Sets user-specified entitlement information or automatically determines what should be used based on Subscription -> available units -> units, even if negative
        ///  The first valid entitlement is used if not manually set
        /// </summary>
        private void SetEntitlementInformation()
        {

            // review to ensure this make sense for both unit-based and subscription

            var staticEntitlementTypes = GetAssessmentTypes().Items.Where(type => type.ScanType.Equals("Static") && !type.EntitlementId.Equals(-1)); //  && !type.EntitlementId.Equals(-1) && type.UnitsAvailable >= 1
            var subscriptionEntitlements = staticEntitlementTypes.Where(type => type.FrequencyType.Equals("Subscription") && !type.EntitlementId.Equals(-1)); // && !type.EntitlementId.Equals(-1)

            // lookup the correct frequency type by the user-specified entitlement ID

            if (subscriptionEntitlements.Any())
            {
                _entitlementId = subscriptionEntitlements.First().EntitlementId;
                _entitlementFrequencyType = subscriptionEntitlements.First().FrequencyType;
                Trace.WriteLine($"Note: Auto-selected subscription entitlement ID: {_entitlementId}.");
                return;
            }

            var singlescanEntitlements = staticEntitlementTypes.Where(type => type.FrequencyType.Equals("SingleScan"));

            if (singlescanEntitlements.Any())
            {
                _entitlementId = singlescanEntitlements.First().EntitlementId;
                _entitlementFrequencyType = singlescanEntitlements.First().FrequencyType;
                Trace.WriteLine($"Note: Auto-selected single scan entitlement ID: {_entitlementId}.");
                return;
            }

            // Will attempt to start scan with negative entitlement. This is caught on the api side if entitlements are required to start a scan.
            _entitlementFrequencyType = "SingleScan";
            _entitlementId = -1;
            Trace.WriteLine($"Note: Auto-selected single scan entitlement ID: {_entitlementId}.");
            return;
        }

        /// <summary>
        /// Writes all non-premiums static assessment types to the console
        /// </summary>
        public void ListAssessmentTypes()
        {
            // I'm leaving premium assessments out since they have a corresponding entitlement to use for static only

            var staticAssessmentTypes = GetAssessmentTypes().Items.Where(type => type.ScanType.Equals("Static") && !type.EntitlementId.Equals(-1));  // && !type.EntitlementId.Equals(-1)

            Trace.WriteLine("Listing all valid assessment types...");
            Trace.WriteLine(Environment.NewLine);

            foreach (var assessmentType in staticAssessmentTypes)
            {
                Trace.WriteLine(assessmentType.Name);
                Trace.WriteLine($"ID: {assessmentType.EntitlementId}");
                Trace.WriteLine($"Frequency Type: {assessmentType.FrequencyType}");
                Trace.WriteLine($"Units Available: {assessmentType.UnitsAvailable}");
                Trace.WriteLine(string.IsNullOrEmpty(assessmentType.SubscriptionEndDate)
                    ? "End Date: N/A"
                    : $"End Date: {assessmentType.SubscriptionEndDate}");

                Trace.WriteLine(Environment.NewLine);
            }
        }
        private RestRequest AddAssessmentParameters(RestRequest request)
        {
            // add tenant/scan parameters
            request.AddQueryParameter("releaseId", _queryParameters.Get("pv"));
            request.AddQueryParameter("assessmentTypeId", _queryParameters.Get("astid"));
            request.AddQueryParameter("technologyStack", _queryParameters.Get("ts"));

            request.AddQueryParameter("entitlementId", _entitlementId.ToString());
            request.AddQueryParameter("entitlementFrequencyType", _entitlementFrequencyType);

            // Language level should only be set on the following language types
            if (_queryParameters.Get("ts").Equals("JAVA/J2EE") || _queryParameters.Get("ts").Equals(".NET") || _queryParameters.Get("ts").Equals("PYTHON"))
            {
                request.AddQueryParameter("languageLevel", _queryParameters.Get("ll"));
            }

            if (_doOpensourceReport)
            {
                request.AddQueryParameter("doSonatypeScan", "true");
            }
            if (_doAutomatedAudit)
            {
                request.AddQueryParameter("auditPreferenceType", "2");
            }
            if (_doExpressScan)
            {
                request.AddQueryParameter("scanPreferenceType", "2");
            }
            if (_includeThirdParty)
            {
                request.AddQueryParameter("excludeThirdPartyLibs", "false");
            }
            if (!_includeThirdParty)
            {
                request.AddQueryParameter("excludeThirdPartyLibs", "true");
            }
            return request;
        }
        #endregion


    }
}
