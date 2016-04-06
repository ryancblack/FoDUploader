# FoDUploader
.NET Fortify on Demand assessment uploader

*** Not for production use ***

*Options*

FoD Uploader 1.0
Copyright (C) 2016 HPE Fortify on Demand, Ryan Black

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


Usage: foduploader.exe --optionName "Value"

