using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoDUploader
{
    class AuthorizationResponse
    {
        public string accessToken { get; set; }
        public string tokenType { get; set; }
        public int expiresInSeconds { get; set; }
        public string refreshToken { get; set; }
        public string scope { get; set; }

    }
}
