using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoDUploader.API
{
    /// <summary>
    /// Error Response
    /// </summary>
    public class ErrorResponse
    {
        /// <summary>
        /// List of errors
        /// </summary>
        public List<ErrorDTO> Errors { get; set; }

        /// <summary>
        /// Constructor
        /// </summary>
        public ErrorResponse()
        {
            Errors = new List<ErrorDTO>();
        }
    }

    /// <summary>
    /// Error
    /// </summary>
    public class ErrorDTO
    {
        /// <summary>
        /// The error code
        /// </summary>
        public int? ErrorCode { get; set; }

        /// <summary>
        /// The error message
        /// </summary>
        public string Message { get; set; }
    }
}
