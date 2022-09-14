# Get-MpPreference
This is a overload function that will call Get-MpPreference and Get-MpComputerStatus from the Microsoft Defender Antivirus policies with full details on each Setting

> Example 1: Get-MpPreference -DisplayAllResults

    This will retrieve all of the settings and display the information to the console. 

> Example 2: Get-MpPreference -DisplayPolicySettings -DisplaySignatureSettings

    This will retrieve the settings and display the antivirus policy and signature information to the console. 

   <span style="color:orange">NOTE:</span> Default is to not display information on the console.

> Example 3: Get-MpPreference -Verbose

    This will retrieve the settings and display verbose information

> Example 4: Get-MpPreference -ExportPath "c:\YourDirectory" -ExportFile "MyErrorLog.txt" -SaveResults

    This will retrieve the settings and save them to your custom path and filename

> Example 6: Get-MpPreference -SaveResults

    This will retrieve the settings and save them to the temp location

> Example 7: Get-MpPreference -DisplayTamperProtectionSettings -DisplayWindowsDefenderSettings -DisplaySignatureSettings -DisplayAvSettings

    This will retrieve the Tamper Protection, Windows Defender, Signature and Antivirus settings and display them to the console



<span style="color:orange">NOTE:</span> All errors are saved to "$env:TEMP\MpPreferenceErrors.txt"
