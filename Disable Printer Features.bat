:: ----------------------------------------------------------
:: --------Disable "Internet Printing Client" feature--------
:: ----------------------------------------------------------
echo --- Disable "Internet Printing Client" feature
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-InternetPrinting-Client" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: -----------Disable "LPD Print Service" feature------------
:: ----------------------------------------------------------
echo --- Disable "LPD Print Service" feature
dism /Online /Disable-Feature /FeatureName:"LPDPrintService" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------------Disable "LPR Port Monitor" feature------------
:: ----------------------------------------------------------
echo --- Disable "LPR Port Monitor" feature
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-LPRPortMonitor" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------Disable "Microsoft Print to PDF" feature---------
:: ----------------------------------------------------------
echo --- Disable "Microsoft Print to PDF" feature
dism /Online /Disable-Feature /FeatureName:"Printing-PrintToPDFServices-Features" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: --------------Disable "XPS Services" feature--------------
:: ----------------------------------------------------------
echo --- Disable "XPS Services" feature
dism /Online /Disable-Feature /FeatureName:"Printing-XPSServices-Features" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ---------------Disable "XPS Viewer" feature---------------
:: ----------------------------------------------------------
echo --- Disable "XPS Viewer" feature
dism /Online /Disable-Feature /FeatureName:"Xps-Foundation-Xps-Viewer" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ------Disable "Print and Document Services" feature-------
:: ----------------------------------------------------------
echo --- Disable "Print and Document Services" feature
dism /Online /Disable-Feature /FeatureName:"Printing-Foundation-Features" /NoRestart
:: ----------------------------------------------------------


:: ----------------------------------------------------------
:: ----------Disable "Work Folders Client" feature-----------
:: ----------------------------------------------------------
echo --- Disable "Work Folders Client" feature
dism /Online /Disable-Feature /FeatureName:"WorkFolders-Client" /NoRestart
:: ----------------------------------------------------------


pause
# Credits go to https://privacy.sexy for creating this amazing code.
exit /b 0