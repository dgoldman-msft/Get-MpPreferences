# Get-MpPreferences
This is a overload function that will call Get-MpPreferences from the Microsoft Defender Antivirus policies with full details on each Setting

> Example 1: Get-MpPreferences -DisplayResults

    This will retrieve the settings and save them to the default location of "$env:TEMP\\MpPreferencesOutput.txt" and display the information to the console. 

   <span style="color:orange">NOTE:</span> Default is to not display information on the screen.

> Example 2 : Get-MpPreferences

    This will retrieve the settings and save them to the default location of "c:\temp\MpPreferencesOutput.txt"

> Example 3: Get-MpPreferences -Verbose

    This will retrieve the settings and save them to the default location of "$env:TEMP\MpPreferencesOutput.txt" and display verbose information

> Example 4: Get-MpPreferences -ExportPath "c:\YourDirectory" -ExportFile "MyErrorLog.txt"

    This will retrieve the settings and save them to your custom path and filename