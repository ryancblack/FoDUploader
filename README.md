# FoDUploader
This is a .NET Fortify on Demand assessment uploader with several convenience features.

Why use this over, or migrate to this from, the existing Java tool?

* Not Java; the only dependency is .NET 4.5+
* Package a folder as a ZIP, or use an existing ZIP, determined by --source
* Logging, status and errors are written to a log in temp - useful for "headless" instances like with TFS post-build actions or troubleshooting
* File filtering - by default the uploader will filter submitted code for what SCA can scan, leaving out graphics etc. This can be disabled, but taking advantage of this can greatly reduce submission time 

Proxy connections are supported automatically provided they are configured in Internet Explorer	on the system.

**Options**

FoD Uploader 1.02
Copyright (C) 2016 HPE Fortify on Demand, Ryan Black ryan.black@hpe.com

  --source               Required. The ZIP file, or directory to be zipped, for submission to Fortify on Demand.

  --username             Your portal username.

  --password             Your portal password.

  --apiToken             Your api token.

  --apiTokenSecret       Your api token secret key.

  --uploadURL            Required. Your BSI URL for the target application,
                         obtained in the customer portal.

  --opensourceReport       (Default: False) If set to true, and enabled in the
                         tenant, an open-source report will be requested.

  --automatedAudit       (Default: False) If set to true, and enabled in the
                         tenant, the Automated Audit feature will be requested.

  --expressScan          (Default: False) If set to true, and enabled in the
                         tenant, the Express Scan feature will be requested.

  --includeThirdParty    (Default: False) If set to true third-party libraries
                         will be included in assessment results.

  --debug				 (Default: False) API calls and post data will be written to the log and console.

  --includeAllFiles	     (Default: False) If set to true all files, including extraneous non-scannable content, will be submitted to Fortify on Demand. The default of "false" will greatly reduce the size of the submission with no impact to assessment quality.


Usage: foduploader.exe --optionName "Value"

