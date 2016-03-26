using System;
using System.Collections.Generic;
using System.Text;
using RestSharp;
using RestSharp.Deserializers;
using RestSharp.Authenticators;
using System.Web;
using System.Net;
using System.Collections.Specialized;
using System.IO;

namespace FoDUploader
{
    class FoDAPI
    {
        private string apiToken;
        private string apiSecret;
        private string userName;
        private string password;
        private string uploadURL;
        private string submissionZIP;

        private bool doSonatypeReport;
        private bool doExpressScan;
        private bool doAutomatedAudit;

        private bool isProxied;
        private bool isTokenAuth;

        private string proxyURI;
        private string proxyUsername;
        private string proxyPassword;
        private string ntDomain;
        private string ntWorkstation;

        private string accessToken;

        private UriBuilder baseURI;
        private NameValueCollection queryParameters;

        private bool lastFragment = false;
        private const long SEGLEN = 1024 * 1024;  // 1Mb chunk size
        private const int GLOBALTIMEOUTINMINUTES = 1 * 60000;
        private long MbbytesSent = 0;


        public FoDAPI(Options options, string submissionZIP)
        {
            this.baseURI = new UriBuilder(options.uploadURL);
            this.queryParameters = GetqueryParameters(this.baseURI);
            this.isTokenAuth = (string.IsNullOrWhiteSpace(options.username)) ? true : false;
            this.submissionZIP = submissionZIP;
            this.apiToken = options.apiToken;
            this.apiSecret = options.apiTokenSecret;
            this.userName = options.username;
            this.password = options.password;
            this.doAutomatedAudit = options.automatedAudit;
            this.doSonatypeReport = options.sonatypeReport;
            this.doExpressScan = options.expressScan;
        }

        private IRestResponse SendData(RestClient client, RestRequest request, byte[] data, long fragNo, long offset)
        {
            //pg. 134 API guide

            // add fragment parameters

            request.AddParameter("fragNo", fragNo, ParameterType.QueryString);
            request.AddParameter("len", data.Length, ParameterType.QueryString);
            request.AddParameter("offset", offset, ParameterType.QueryString);
            request.AddParameter("application/octet-stream", data, ParameterType.RequestBody);

            var postURI = client.BuildUri(request).AbsoluteUri;

            Console.WriteLine("POST string: {0}", postURI);

            var response = client.Execute(request);

            return response;

        }

        public void SendScanPost()
        {
            long fragNo = 0;
            long offset = 0;

            // The max size we're allowing is 5GB, that's big, but it's abnormal for anything to be closer to 1GB - should be okay to read right into mem, for now, still should improve this
            byte[] zipfile = File.ReadAllBytes(submissionZIP);
            byte[] sendByteBuffer;
            long zipFileSize = zipfile.LongLength;

            // endpoint https://www.hpfod.com/api/v1/Release/{releaseId}/scan/
            // parameters ?assessmentTypeId=&technologyStack=&languageLevel=&fragNo=&offset=&

            StringBuilder endpoint = new StringBuilder();
            endpoint.Append(baseURI.Scheme + "://");
            endpoint.Append(baseURI.Host + "/");
            endpoint.Append("api/v1/Release/");
            endpoint.Append(queryParameters.Get("pv"));
            endpoint.Append("/scan/");

            var client = new RestClient(endpoint.ToString());
            client.Timeout = GLOBALTIMEOUTINMINUTES * 120;
            var request = new RestRequest(Method.POST);

            request.AddHeader("Authorization", "Bearer " + apiToken);
            request.AddHeader("Content-Type", "application/octet-stream");

            // add tenant/scan parameters

            request.AddParameter("assessmentTypeId", queryParameters.Get("astid"), ParameterType.QueryString);
            request.AddParameter("technologyStack", queryParameters.Get("ts"), ParameterType.QueryString);
            request.AddParameter("languageLevel", queryParameters.Get("ll"), ParameterType.QueryString);

            // add optional assessment parameters for sonatype, automated audit, express scanning

            request = AddOptionalParameters(request);

            // go over file and send chunks
            // for (length of file in bytes by chunk size) SendData()

            // sending it all for now (lol)

            try
            {
                var IRestResponse = SendData(client, request, zipfile, -1, 0);
                if (IRestResponse.Content.ToString() == "ACK")
                {
                    Console.WriteLine("Assessment submission successful!");
                }
                else
                {
                    Console.WriteLine("Error submitting to Fortify on Demand: {0}", IRestResponse.Content.ToString());
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex);
                throw;
            }
        }


        /// <summary>
        /// Obtains, or updates, the authorization token for FoD. If isAuthToken is true client_credentials will be used instead of password
        /// </summary>
        public bool Authorize()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(baseURI.Scheme);
            sb.Append("://");
            sb.Append(baseURI.Host + "/");
            sb.Append("oauth/token");

            var client = new RestClient(sb.ToString());
            var request = new RestRequest("", Method.POST);

            request.AddParameter("scope", "https://hpfod.com/tenant");

            if (isTokenAuth)
            {
                request.AddParameter("grant_type", "client_credentials");
                request.AddParameter("client_id", apiToken);
                request.AddParameter("client_secret", apiSecret);
            }
            else
            {
                request.AddParameter("grant_type", "password");
                request.AddParameter("username", userName);
                request.AddParameter("password", password);
            }

            try
            {
                var response = client.Execute(request);
                apiToken = new JsonDeserializer().Deserialize<AuthorizationResponse>(response).accessToken;
            }
            catch (Exception ex)
            {
                apiToken = null;
                Console.WriteLine(ex.Message);
                return false;
            }
            return true;
        }

        private RestRequest AddOptionalParameters(RestRequest request)
        {
            if (doSonatypeReport)
            {
                request.AddQueryParameter("doSonatypeScan", "true");
            }
            if (doAutomatedAudit)
            {
                request.AddQueryParameter("auditPreferenceId", "2");
            }
            if (doExpressScan)
            {
                request.AddQueryParameter("scanPreferenceId", "2");
            }
            return request;
        }

        public bool isLoggedIn()
        {
            if (string.IsNullOrWhiteSpace(accessToken))
            {
                return false;
            }
            return true;
        }


        public void RetireToken()
        {
            StringBuilder sb = new StringBuilder();
            sb.Append(baseURI.Scheme);
            sb.Append("://");
            sb.Append(baseURI.Host + "/");
            sb.Append("oauth/retireToken");

            var client = new RestClient(sb.ToString());
            var request = new RestRequest("", Method.GET);

            request.AddHeader("Auhorization", "Bearer " + accessToken);

            try
            {
                var response = client.Execute(request);
                apiToken = new JsonDeserializer().Deserialize<AuthorizationResponse>(response).accessToken;
            }
            catch (Exception ex)
            {
                apiToken = null;
                Console.WriteLine(ex.Message);
                throw;
            }
        }

        private NameValueCollection GetqueryParameters(UriBuilder postURL)
        {
            NameValueCollection queryParameters = HttpUtility.ParseQueryString(postURL.Query);
            return queryParameters;
        }
    }
}
