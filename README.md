# FoDUploader
.NET Fortify on Demand assessment uploader

*This software is provided as a sample only, and while tested, not intended for production use*

**Options**

FoD Uploader 1.0
Copyright (C) 2016 HPE Fortify on Demand, Ryan Black ryan.black@hpe.com

  --source               Required. The ZIP file, or directory to be zipped, for
                         submission to Fortify on Demand

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

  --includeAllPayload	 (Default: False) If set to true all files, including extraneous non-scannable content, will be submitted to Fortify on Demand. The default of "false" will greatly reduce the size of the submission with no impact to assessment quality.


Usage: foduploader.exe --optionName "Value"

