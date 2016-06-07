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
using System.Text;
using System.Web;
using FoDUploader.API;
using RestSharp;
using RestSharp.Deserializers;

namespace FoDUploader
{
    internal class FoDapi
    {
        private readonly string _apiToken;
        private readonly string _apiSecret;
        private readonly string _userName;
        private readonly string _password;
        private readonly string _submissionZip;

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

        public bool DoOpensourceReport { get; }

        public FoDapi(Options options, string zip)
        {
            _baseUri = new UriBuilder(options.UploadUrl);
            _queryParameters = GetqueryParameters(_baseUri);
            _isTokenAuth = (string.IsNullOrWhiteSpace(options.Username));
            _submissionZip = zip;
            _apiToken = options.ApiToken;
            _apiSecret = options.ApiTokenSecret;
            _userName = options.Username;
            _password = options.Password;
            _doAutomatedAudit = options.AutomatedAudit;
            DoOpensourceReport = options.OpensourceReport;
            _doExpressScan = options.ExpressScan;
            _includeThirdParty = options.IncludeThirdParty;
            _isDebug = options.Debug;
        }

        private IRestResponse SendData(RestClient client, byte[] data, long fragNo, long offset)
        {

            var request = new RestRequest(Method.POST);

            request.AddHeader("Authorization", "Bearer " + _accessToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            // add tenant/scan parameters

            request.AddQueryParameter("assessmentTypeId", _queryParameters.Get("astid"));
            request.AddQueryParameter("technologyStack", _queryParameters.Get("ts"));

            if (_queryParameters.Get("ts").Equals("JAVA/J2EE") || _queryParameters.Get("ts").Equals(".NET") || _queryParameters.Get("ts").Equals("PYTHON"))
            {
                request.AddQueryParameter("languageLevel", _queryParameters.Get("ll"));
            }

            // add optional assessment parameters for sonatype, automated audit, express scanning

            request = AddOptionalParameters(request);

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
                if (httpStatus.Equals("OK"))
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

        public void SendScanPost()
        {
            var fi = new FileInfo(_submissionZip);

            Trace.WriteLine("Beginning upload....");
            // endpoint https://www.hpfod.com/api/v1/Release/{releaseId}/scan/
            // parameters ?assessmentTypeId=&technologyStack=&languageLevel=&fragNo=&offset=&

            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v1/Release/");
            endpoint.Append(_queryParameters.Get("pv"));
            endpoint.Append("/scan/");

            var client = new RestClient(endpoint.ToString()) {Timeout = Globaltimeoutinminutes*120};

            // Read it in chunks
            var uploadStatus = "";           

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
                            var lastPost = SendData(client, sendByteBuffer, fragmentNumber, offset);
                            uploadStatus = lastPost.StatusCode.ToString();
                            break;
                        }
                        Array.Copy(readByteBuffer, sendByteBuffer, sendByteBuffer.Length);
                        var post = SendData(client, sendByteBuffer, fragmentNumber++, offset);
                        uploadStatus = post.StatusCode.ToString();
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
                    Trace.WriteLine("Error submitting to Fortify on Demand.");
                    Environment.Exit(-1);
                }
            }
        }


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

        private RestRequest AddOptionalParameters(RestRequest request)
        {
            if (DoOpensourceReport)
            {
                request.AddQueryParameter("doSonatypeScan", "true");
            }
            if (_doAutomatedAudit)
            {
                request.AddQueryParameter("auditPreferenceId", "2");
            }
            if (_doExpressScan)
            {
                request.AddQueryParameter("scanPreferenceId", "2");
            }
            if (_includeThirdParty) // I am unsure if it's safe to let the default work so I'm explicit. 
            {
                request.AddQueryParameter("excludeThirdPartyLibs", "false");
            }
            if (!_includeThirdParty)
            {
                request.AddQueryParameter("excludeThirdPartyLibs", "true");
            }
            return request;
        }

        public ReleaseResponse GetReleaseInfo()
        {

            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v1/Release/");
            endpoint.Append(_queryParameters.Get("pv"));

            var client = new RestClient(endpoint.ToString()) {Timeout = Globaltimeoutinminutes*120};
            var request = new RestRequest(Method.GET);

            request.AddHeader("Authorization", "Bearer " + _accessToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            try
            {
               var response = client.Execute(request);
               var release = new JsonDeserializer().Deserialize<ReleaseResponse>(response);
                return release;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                throw;
            }
        }

        public TenantEntitlementQuery GetEntitlementInfo()
        {
            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v2/TenantEntitlements");

            var client = new RestClient(endpoint.ToString()) {Timeout = Globaltimeoutinminutes*120};
            var request = new RestRequest(Method.GET);

            request.AddHeader("Authorization", "Bearer " + _accessToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            try
            {
                var response = client.Execute(request);
                if (response.StatusDescription.Equals("Unauthorized"))
                {
                    Trace.WriteLine("Note: Your token is not authorized to retrieve entitlement information. Please use higher privilege authentication if you would like this information displayed in this utility.");
                }
                var entitlements = new JsonDeserializer().Deserialize<TenantEntitlementQuery>(response);
                return entitlements;
            }
            catch (Exception ex)
            {
                Trace.WriteLine(ex);
                throw;
            }

        }

        public Features GetFeatureInfo()
        {
            var endpoint = new StringBuilder();
            endpoint.Append(_baseUri.Scheme + "://");
            endpoint.Append(_baseUri.Host + "/");
            endpoint.Append("api/v3/tenants/features");

            var client = new RestClient(endpoint.ToString()) {Timeout = Globaltimeoutinminutes*120};
            var request = new RestRequest(Method.GET);

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

        public bool IsLoggedIn()
        {
            return !string.IsNullOrWhiteSpace(_accessToken);
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

        private NameValueCollection GetqueryParameters(UriBuilder postUrl)
        {
            var queryParameters = HttpUtility.ParseQueryString(postUrl.Query);
            return queryParameters;
        }
    }
}
