# Get-MpPreferences
This is a overload function that will call Get-MpPreferences and Get-MpComputerStatus from the Microsoft Defender Antivirus policies with full details on each Setting

> Example 1: Get-MpPreferences -DisplayAllResults

    This will retrieve all of the settings and display the information to the console. 

> Example 2: Get-MpPreferences -DisplayPolicySettings -DisplaySignatureSettings

    This will retrieve the settings and display the antivirus policy and signature information to the console. 

   <span style="color:orange">NOTE:</span> Default is to not display information on the console.

> Example 3: Get-MpPreferences -Verbose

    This will retrieve the settings and display verbose information

> Example 4: Get-MpPreferences -ExportPath "c:\YourDirectory" -ExportFile "MyErrorLog.txt" -SaveResults

    This will retrieve the settings and save them to your custom path and filename

> Example 6: Get-MpPreferences -SaveResults

    This will retrieve the settings and save them to the temp location

> Example 7: Get-MpPreferences -DisplayTamperProtectionSettings -DisplayWindowsDefenderSettings -DisplaySignatureSettings -DisplayAvSettings

    This will retrieve the Tamper Protection, Windows Defender, Signature and Antivirus settings and display them to the console



<span style="color:orange">NOTE:</span> All errors are saved to "$env:TEMP\MpPreferenceErrors.txt"
