# FoDUploader
This project is a MIT-licensed .NET Fortify on Demand assessment uploader with several convenience features.

* Requires NET 4.5+
* Checks that an assessment for the target application is not in progress/paused before attempting to upload 
* Checks for correct entitlement to scan before attempting to upload
* Notifies if a selected assessment option, e.g. open-source reporting, Automated Audit, or Express Scan are requested, but not enabled for the account
* Package a folder as a ZIP, or use an existing ZIP, determined by --source
* Logging, status and errors are written to a log in temp - useful for "headless" instances like with TFS post-build actions or troubleshooting
* File filtering - by default the uploader will filter submitted code for what SCA can scan, leaving out graphics etc. This can be disabled, but taking advantage of this can greatly reduce submission time 

Proxy connections are supported automatically provided they are configured in Internet Explorer	on the system.

**Options**

FoD Uploader
Copyright (C) 2016 HPE Security Fortify on Demand, Ryan Black - ryan.black@hpe.com

  --source                The path of the ZIP file, or directory to be 
                          zipped, for submission to Fortify on Demand.

  --username              Your portal username.

  --password              Your portal password.

  --apiToken              Your api token.

  --apiTokenSecret        Your api token secret key.

  --uploadURL             Required. Your BSI URL for the target application, 
                          obtained in the customer portal.

  --opensourceReport      (Default: False) If set to true, and enabled in the 
                          tenant, an open-source report will be requested.

  --automatedAudit        (Default: False) If set to true, and enabled in the 
                          tenant, the Automated Audit feature will be requested.

  --expressScan           (Default: False) If set to true, and enabled in the 
                          tenant, the Express Scan feature will be requested.

  --includeThirdParty     (Default: False) If set to true third-party libraries
                          will be included in assessment results.

  --includeAllFiles       (Default: False) If set to true all files, including 
                          extraneous non-scannable content, will be submitted 
                          to Fortify on Demand. The default of "false" will 
                          greatly reduce the size of the submission with no 
                          impact to assessment quality.

  --displayEntitlement    (Default: False) Displays entitlement information 
                          related to the application release ID. This option 
                          may be used to determine which entitlement is desired
                          for manual specification; if enabled no assessment is
                          submitted.

  --entitlementId         Optionally set an entitlement ID to use for the 
                          assessment.

  --debug                 (Default: False) Verbose setting, API call, POST 
                          detail, and entitlement information will be written 
                          to the console.


Usage: foduploader.exe --optionName "Value"


