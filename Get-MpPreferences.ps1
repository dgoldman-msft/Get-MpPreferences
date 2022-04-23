function Get-MpPreferences {
    <#
    .SYNOPSIS
        Get Windows Defender Policy Settings

    .DESCRIPTION
        This is a overload function that will call Get-MpPreferences from the Microsoft Defender Antivirus policies with full details on each Setting

    .PARAMETER AmResultsExportFile
        Computer antivirus output file name

    .PARAMETER DisplayAmSettings
        Switch used to display antivirus policy results to the console

    .PARAMETER DisplayScannerSettings
        Switch used to display scanner settings to the console

    .PARAMETER DisplaySignatureSettings
        Switch used to display antivirus signature results to the console

    .PARAMETER DisplayTamperProtectionSettings
        Switch used to display tamper protection results to the console

    .PARAMETER DisplayWindowsDefenderSettings
        Switch used to display policy to the console

    .PARAMETER ErrorLog
        Error log name

    .PARAMETER ExportFile
        Output file name

    .PARAMETER ExportPath
        Output file location

    .PARAMETER SaveResults
        Save all files to disk

    .PARAMETER SignatureResultsExportFile
        Computer antivirus signature output file name

    .EXAMPLE
        C:\PS> Get-MpPreferences -DisplayWindowsDefenderSettings

        This will retrieve the settings and save them to the default location of "$env:TEMP\\MpPreferencesOutput.txt" and display the information to the console

    .EXAMPLE
        C:\PS> Get-MpPreferences

        This will retrieve the settings and save them to the default location of "c:\temp\MpPreferencesOutput.txt"

    .EXAMPLE
        C:\PS> Get-MpPreferences -Verbose

        This will retrieve the settings and save them to the default location of "$env:TEMP\MpPreferencesOutput.txt" and display verbose information

    .EXAMPLE
        C:\PS> Get-MpPreferences -ExportPath "c:\YourDirectory" -ExportFile "MyErrorLog.txt"

        This will retrieve the settings and save them to your custom path and filename

    .EXAMPLE
        C:\PS> Get-MpPreferences -DisplayTamperProtectionSettings -DisplayWindowsDefenderSettings -DisplaySignatureSettings -DisplayAmSettings

        This will retrieve the Tamper Protection, Windows Defender, Signature and Antivirus settings and display them to the console

    .EXAMPLE
        C:\PS> GetSettings

        You can also use an alias to run the method

    .NOTES
        This just invokes the Get-MpPreference cmdlet and writes up the full details in a readable format
    #>

    [OutputType('System.String')]
    [OutputType('PSCustomObject')]
    [CmdletBinding()]
    [Alias('GetSettings')]
    param(
        [string]
        $AmResultsExportFile = 'AvOutput.txt',

        [switch]
        $DisplayAmSettings,

        [switch]
        $DisplayScannerSettings,

        [switch]
        $DisplaySignatureSettings,

        [switch]
        $DisplayTamperProtectionSettings,

        [switch]
        $DisplayWindowsDefenderSettings,

        [string]
        $ErrorLog = 'MpPreferenceErrors.txt',

        [string]
        $MpExportFile = 'MpPreferencesOutput.txt',

        [string]
        $ExportPath = "$env:TEMP",

        [switch]
        $SaveResults,

        [string]
        $SignatureResultsExportFile = 'AvSignatureOutput.txt'
    )

    begin {
        Write-Output 'Checking for and importing the Microsoft Defender module'
        $parameters = $PSBoundParameters
        $antimalwareSettings = 'Antimalware Settings'
        $signatureSettings = 'Antimalware Signature Settings'
        $tamperProtectionSettings = 'Tamper Protection Settings'
        $windowsDefenderSettings = 'Windows Defender Scans & Update Preferences'
        $windowsDefenderScannerSettings = 'Windows Defender Scanner Settings'
    }

    process {
        try {
            Write-Output "Getting ConfigDefender Antivirus preferences`n"
            $preferences = Get-MpPreference -ErrorAction Stop

            #region Customizations
            # Windows Defender scans and updates
            switch ($preferences.DefinitionUpdatesChannel) {
                0x0 { $definitionUpdatesChannel = 'NotConfigured. Devices stay up to date automatically during the gradual release cycle. This value is suitable for most devices.' }
                0x1 { $definitionUpdatesChannel = 'Broad. Devices are offered updates only after the gradual release cycle completes. This value is suggested for a broad set of devices in your production population, from 10 to 100 percent.' }
                0x2 { $definitionUpdatesChannel = 'Staged. Devices are offered updates after the monthly gradual release cycle. This value is suggested for a small, representative part of your production population, around 10 percent.' }
            }

            # Specifies the state for the controlled folder access feature
            switch ($preferences.EnableControlledFolderAccess) {
                0x0 { $enableControlledFolderAccess = 'Disabled' }
                0x1 { $enableControlledFolderAccess = 'Enabled' }
                0x2 { $enableControlledFolderAccess = 'Set to Audit Mode' }
            }

            # Specifies how the network protection service handles web-based malicious threats, including phishing and malware
            switch ($preferences.EnableNetworkProtection) {
                0x0 { $enableNetworkProtection = 'Disabled' }
                0x1 { $enableNetworkProtection = 'Enabled' }
                0x2 { $enableNetworkProtection = 'Set to Audit Mode' }
            }

            # Specifies which automatic remediation action to take for a low level threat
            switch ($preferences.LowThreatDefaultAction) {
                0x0 { $lowThreatDefaultAction = 'Set to Quarantine' }
                0x1 { $lowThreatDefaultAction = 'Set to Remove' }
                0x2 { $lowThreatDefaultAction = 'Set to Ignore' }
            }

            # Specifies which automatic remediation action to take for a moderate level threat
            switch ($preferences.ModerateThreatDefaultAction) {
                0x0 { $moderateThreatDefaultAction = 'Set to Quarantine' }
                0x1 { $moderateThreatDefaultAction = 'Set to Remove' }
                0x2 { $moderateThreatDefaultAction = 'Set to Ignore' }
            }

            # Specifies which automatic remediation action to take for a high level threat
            switch ($preferences.HighThreatDefaultAction) {
                0x0 { $highThreatDefaultAction = 'Set to Quarantine' }
                0x1 { $highThreatDefaultAction = 'Set to Remove' }
                0x2 { $highThreatDefaultAction = 'Set to Ignore' }
            }

            # Specifies the type of membership in Microsoft Active Protection Service. Microsoft Active Protection Service is an online community that helps you choose how to respond to potential threats. The community also helps prevent the spread of new malicious software.
            switch ($preferences.MAPSReporting) {
                0x0 { $MAPSReporting = 'Disabled. Send no information to Microsoft' }
                0x1 { $MAPSReporting = 'Set to Basic membership. Send basic information to Microsoft about detected software, including where the software came from, the actions that you apply or that apply automatically, and whether the actions succeeded.' }
                0x2 { $MAPSReporting = 'Set to Advanced membership. In addition to basic information, send more information to Microsoft about malicious software, spyware, and potentially unwanted software, including the location of the software, file names, how the software operates, and how it affects your computer.' }
            }

            # Specifies when devices receive Microsoft Defender platform updates during the monthly gradual rollout
            switch ($preferences.PlatformUpdatesChannel) {
                0x0 { $platformUpdatesChannel = 'NotConfigured. Devices stay up to date automatically during the gradual release cycle. This value is suitable for most devices.' }
                0x1 { $platformUpdatesChannel = 'Set to Beta. Devices are the first to receive new updates. Select Beta Channel to participate in identifying and reporting issues to Microsoft. Devices in the Windows Insider Program are subscribed to this channel by default. This value is for use in manual test environments only and a limited number of devices.' }
                0x2 { $platformUpdatesChannel = 'Set to Broad. Devices are offered updates only after the gradual release cycle completes. This value is suggested for a broad set of devices in your production population, from 10 to 100 percent.' }
                0x3 { $platformUpdatesChannel = 'Set to Broad. Devices are offered updates only after the gradual release cycle completes. This value is suggested for a broad set of devices in your production population, from 10 to 100 percent.' }
                0x4 { $platformUpdatesChannel = 'Set to Preview. Devices are offered updates earliest during the monthly gradual release cycle. This value is suggested for pre-production or validation environments.' }
                0x5 { $platformUpdatesChannel = 'Set to Staged. Devices are offered updates after the monthly gradual release cycle. This value is suggested for a small, representative part of your production population, around 10 percent.' }
            }

            # Proxy settings
            if (-NOT ($preferences.ProxyBypass)) { $proxyBypass = 'No Proxy Bypass Detected' } else { $proxyBypass = $preferences.ProxyBypass }
            if (-NOT ($preferences.ProxyPacUrl)) { $proxyPacUrl = 'No Proxy Pac URL Detected' } else { $proxyPacUrl = $preferences.ProxyPacUrl }
            if (-NOT ($preferences.ProxyServer)) { $proxyServer = 'No Proxy Server Detected' } else { $proxyServer = $preferences.ProxyServer }

            # Specifies the level of detection for potentially unwanted applications. When potentially unwanted software is downloaded or attempts to install itself on your computer, you are warned
            switch ($preferences.PUAProtection) {
                0x0 { $pUAProtection = 'Disabled' }
                0x1 { $pUAProtection = 'Enabled' }
                0x2 { $pUAProtection = 'Set to Audit Mode' }
            }

            # Specifies scanning configuration for incoming and outgoing files on NTFS volumes.
            switch ($preferences.RealTimeScanDirection) {
                0x0 { $realTimeScanDirection = 'Default - Scan both incoming and outgoing files' }
                0x1 { $realTimeScanDirection = 'Scan incoming files only' }
                0x2 { $realTimeScanDirection = 'Scan outgoing files only' }
            }

            # Specifies the day of the week on which to perform a scheduled full scan in order to complete remediation. Alternatively, specify everyday for this full scan or never.
            switch ($preferences.RemediationScheduleDay) {
                0x0 { $remediationScheduleDay = 'Set to Everyday' }
                0x1 { $remediationScheduleDay = 'Set to Sunday' }
                0x2 { $remediationScheduleDay = 'Set to Monday' }
                0x3 { $remediationScheduleDay = 'Set to Tueday' }
                0x4 { $remediationScheduleDay = 'Set to Wednesday' }
                0x5 { $remediationScheduleDay = 'Set to Thursday' }
                0x6 { $remediationScheduleDay = 'Set to Friday' }
                0x7 { $remediationScheduleDay = 'Set to Saturday' }
                0x8 { $remediationScheduleDay = 'Set to Never' }
            }

            # Specifies the number of minutes before a detection in the additional action state changes to the cleared state.
            $reportingAdditionalActionTimeOut = "$($preferences.ReportingAdditionalActionTimeOut / 60) minutes"

            # Specifies the number of minutes before a detection in the critically failed state changes to either the additional action state or the cleared state
            $reportingCriticalFailureTimeOut = "$($preferences.ReportingCriticalFailureTimeOut / 60) minutes"

            # Specifies the number of minutes before a detection in the non-critically failed state changes to the cleared state
            $reportingNonCriticalTimeOut = "$($preferences.ReportingNonCriticalTimeOut / 60) minutes"

            # Specifies the scan type to use during a scheduled scan
            switch ($preferences.ScanParameters) {
                0x1 { $scanParameters = 'Set to Quick scan' }
                0x2 { $scanParameters = 'Set to Full scan' }
            }

            # Specifies the maximum percentage CPU usage for a scan. The acceptable values for this parameter are: integers from 5 through 100, and the value 0, which disables CPU throttling. Windows Defender does not exceed the percentage of CPU usage that you specify. The default value is 50.
            $scanAvgCPULoadFactor = "$($preferences.ScanAvgCPULoadFactor) %"

            # Specifies the number of days to keep items in the Quarantine folder. If you specify a value of zero or do not specify a value for this parameter, items stay in the Quarantine folder indefinitely.
            if (($preferences.QuarantinePurgeItemsAfterDelay -eq 0) -or (-NOT ($preferences.QuarantinePurgeItemsAfterDelay))) { $quarantinePurgeItemsAfterDelay = 'Items set to stay in the Quarantine folder indefinitely' }
            if ($preferences.QuarantinePurgeItemsAfterDelay -ge 1) { $quarantinePurgeItemsAfterDelay = "$($preferences.QuarantinePurgeItemsAfterDelay) days" }

            # Specifies the number of days to keep items in the scan history folder. After this time, Windows Defender removes the items. If you specify a value of zero, Windows Defender does not remove items. If you do not specify a value, Windows Defender removes items from the scan history folder after the default length of time, which is 15 days
            if ($preferences.ScanPurgeItemsAfterDelay -eq 0) { $scanPurgeItemsAfterDelay = "$($preferences.ScanPurgeItemsAfterDelay) - Windows Defender does not remove items" }

            # Specifies the day of the week on which to perform a scheduled scan. Alternatively, specify everyday for a scheduled scan or never
            switch ($preferences.ScanScheduleDay) {
                0x0 { $scanScheduleDay = 'Set to Everyday' }
                0x1 { $scanScheduleDay = 'Set to Sunday' }
                0x2 { $scanScheduleDay = 'Set to Monday' }
                0x3 { $scanScheduleDay = 'Set to Tueday' }
                0x4 { $scanScheduleDay = 'Set to Wednesday' }
                0x5 { $scanScheduleDay = 'Set to Thursday' }
                0x6 { $scanScheduleDay = 'Set to Friday' }
                0x7 { $scanScheduleDay = 'Set to Saturday' }
                0x8 { $scanScheduleDay = 'Set to Never' }
            }

            # Specifies which automatic remediation action to take for a severe level threat.
            switch ($preferences.SevereThreatDefaultAction) {
                0x0 { $severeThreatDefaultAction = 'Set to Quarantine' }
                0x1 { $severeThreatDefaultAction = 'Set to Remove' }
                0x2 { $severeThreatDefaultAction = 'Set to Ignore' }
            }

            # Specifies a grace period, in minutes, for the definition. If a definition successfully updates within this period, Windows Defender abandons any service initiated updates.
            $signatureAuGracePeriod = "$($preferences.SignatureAuGracePeriod) minutes"

            # Specifies the day of the week on which to check for definition updates. Alternatively, specify everyday for a scheduled scan or never
            switch ($preferences.SignatureScheduleDay) {
                0x0 { $signatureScheduleDay = 'Set to Everyday' }
                0x1 { $signatureScheduleDay = 'Set to Sunday' }
                0x2 { $signatureScheduleDay = 'Set to Monday' }
                0x3 { $signatureScheduleDay = 'Set to Tueday' }
                0x4 { $signatureScheduleDay = 'Set to Wednesday' }
                0x5 { $signatureScheduleDay = 'Set to Thursday' }
                0x6 { $signatureScheduleDay = 'Set to Friday' }
                0x7 { $signatureScheduleDay = 'Set to Saturday' }
                0x8 { $signatureScheduleDay = 'Default - Set to Never' }
            }

            # Specifies the number of days after which Windows Defender requires a catch-up definition update. If you do not specify a value for this parameter, Windows Defender requires a catch-up definition update after the default value of one day
            if ($preferences.SignatureUpdateCatchupInterval -eq 1) { $signatureUpdateCatchupInterval = "$($preferences.SignatureUpdateCatchupInterval) day" } else { $signatureUpdateCatchupInterval = "$($preferences.SignatureUpdateCatchupInterval) day's" }

            # Specifies a grace period, in minutes, for the definition. If a definition successfully updates within this period, Windows Defender abandons any service initiated updates
            $signatureFirstAuGracePeriod = "$($preferences.SignatureFirstAuGracePeriod) minutes"

            # Specifies the interval, in hours, at which to check for definition updates. The acceptable values for this parameter are: integers from 1 through 24. If you do not specify a value for this parameter, Windows Defender checks at the default interval. You can use this parameter instead of the SignatureScheduleDay parameter and SignatureScheduleTime
            $signatureUpdateInterval = "$($preferences.SignatureUpdateInterval) hours"

            # Specifies how Windows Defender checks for user consent for certain samples. If consent has previously been granted, Windows Defender submits the samples. Otherwise, if the MAPSReporting parameter does not have a value of Disabled, Windows Defender prompts the user for consent
            switch ($preferences.SubmitSamplesConsent) {
                0x0 { $submitSamplesConsent = 'Always prompt' }
                0x1 { $submitSamplesConsent = 'Send safe samples automatically' }
                0x2 { $submitSamplesConsent = 'Never send' }
                0x3 { $submitSamplesConsent = 'Send all samples automatically' }
            }

            # Specifies an array of the actions to take for the IDs specified by using the ThreatIDDefaultAction_Ids parameter
            switch ($preferences.ThreatIDDefaultAction_Actions) {
                0x1 { $threatIDDefaultAction_Actions = 'Set to Clean' }
                0x2 { $threatIDDefaultAction_Actions = 'Set to Quarantine' }
                0x3 { $threatIDDefaultAction_Actions = 'Set to Remove' }
                0x6 { $threatIDDefaultAction_Actions = 'Set to Allow' }
                0x8 { $threatIDDefaultAction_Actions = 'Set to UserDefined' }
                0x9 { $threatIDDefaultAction_Actions = 'Set to NoAction' }
                0x10 { $threatIDDefaultAction_Actions = 'Set to Block' }
            }

            # MpEngine
            switch ($preferences.CloudBlockLevel) {
                0x1 { $cloudBlockLevel = '1 = Not Configured - Default Windows Defender blocking level' }
                0x2 { $cloudBlockLevel = '2 = Default blocking level provides strong detection without increasing the risk of detecting legitimate files.' }
                0x3 { $cloudBlockLevel = '3 = Moderate blocking level provides moderate only for high confidence detections' }
                0x4 { $cloudBlockLevel = '4 = High blocking level applies a strong level of detection while optimizing client performance (but can also give you a greater chance of false positives).' }
                0x5 { $cloudBlockLevel = '5 = High + blocking level applies extra protection measures (might affect client performance and increase your chance of false positives).' }
                0x6 { $cloudBlockLevel = '6 = Zero tolerance blocking level – block all unknown executables' }
            }
            #endregion Customizations

            # Windows Defender scans and update preferences
            $policyResults = [PSCustomObject]@{
                AllowDatagramProcessingOnWinServer            = $preferences.AllowDatagramProcessingOnWinServer
                AllowNetworkProtectionDownLevel               = $preferences.AllowNetworkProtectionDownLevel
                AllowNetworkProtectionOnWinServer             = $preferences.AllowNetworkProtectionOnWinServer
                AllowSwitchToAsyncInspection                  = $preferences.AllowSwitchToAsyncInspection
                AttackSurfaceReductionOnlyExclusions          = $preferences.AttackSurfaceReductionOnlyExclusions
                AttackSurfaceReductionRules_Actions           = $preferences.AttackSurfaceReductionRules_Actions
                AttackSurfaceReductionRules_Ids               = $preferences.AttackSurfaceReductionRules_Ids
                CheckForSignaturesBeforeRunningScan           = $preferences.CheckForSignaturesBeforeRunningScan
                CloudBlockLevel                               = $cloudBlockLevel
                CloudExtendedTimeout                          = $preferences.CloudExtendedTimeout
                ComputerID                                    = $preferences.ComputerID
                ControlledFolderAccessAllowedApplications     = $preferences.ControlledFolderAccessAllowedApplications
                ControlledFolderAccessProtectedFolders        = $preferences.ControlledFolderAccessProtectedFolders
                DefinitionUpdatesChannel                      = $definitionUpdatesChannel
                DisableArchiveScanning                        = $preferences.DisableArchiveScanning
                DisableAutoExclusions                         = $preferences.DisableAutoExclusions
                DisableBehaviorMonitoring                     = $preferences.DisableBehaviorMonitoring
                DisableBlockAtFirstSeen                       = $preferences.DisableBlockAtFirstSeen
                DisableCatchupFullScan                        = $preferences.DisableCatchupFullScan
                DisableCatchupQuickScan                       = $preferences.DisableCatchupQuickScan
                DisableCpuThrottleOnIdleScans                 = $preferences.DisableCpuThrottleOnIdleScans
                DisableDatagramProcessing                     = $preferences.DisableDatagramProcessing
                DisableDnsOverTcpParsing                      = $preferences.DisableDnsOverTcpParsing
                DisableDnsParsing                             = $preferences.DisableDnsParsing
                DisableEmailScanning                          = $preferences.DisableEmailScanning
                DisableFtpParsing                             = $preferences.DisableFtpParsing
                DisableGradualRelease                         = $preferences.DisableGradualRelease
                DisableHttpParsing                            = $preferences.DisableHttpParsing
                DisableInboundConnectionFiltering             = $preferences.DisableInboundConnectionFiltering
                DisableIOAVProtection                         = $preferences.DisableIOAVProtection
                DisableNetworkProtectionPerfTelemetry         = $preferences.DisableNetworkProtectionPerfTelemetry
                DisablePrivacyMode                            = $preferences.DisablePrivacyMode
                DisableRdpParsing                             = $preferences.DisableRdpParsing
                DisableRealtimeMonitoring                     = $preferences.DisableRealtimeMonitoring
                DisableRemovableDriveScanning                 = $preferences.DisableRemovableDriveScanning
                DisableRestorePoint                           = $preferences.DisableRestorePoint
                DisableScanningMappedNetworkDrivesForFullScan = $preferences.DisableScanningMappedNetworkDrivesForFullScan
                DisableScanningNetworkFiles                   = $preferences.DisableScanningNetworkFiles
                DisableScriptScanning                         = $preferences.DisableScriptScanning
                DisableSshParsing                             = $preferences.DisableSshParsing
                DisableTDTFeature                             = $preferences.DisableTDTFeature
                DisableTlsParsing                             = $preferences.DisableTlsParsing
                EnableControlledFolderAccess                  = $enableControlledFolderAccess
                EnableDnsSinkhole                             = $preferences.EnableDnsSinkhole
                EnableFileHashComputation                     = $preferences.EnableFileHashComputation
                EnableFullScanOnBatteryPower                  = $preferences.EnableFullScanOnBatteryPower
                EnableLowCpuPriority                          = $preferences.EnableLowCpuPriority
                EnableNetworkProtection                       = $enableNetworkProtection
                EngineUpdatesChannel                          = $preferences.EngineUpdatesChannel
                ExclusionExtension                            = $preferences.ExclusionExtension
                ExclusionIpAddress                            = $preferences.ExclusionIpAddress
                ExclusionPath                                 = $preferences.ExclusionPath
                ExclusionProcess                              = $preferences.ExclusionProcess
                ForceUseProxyOnly                             = $preferences.ForceUseProxyOnly
                HighThreatDefaultAction                       = $highThreatDefaultAction
                LowThreatDefaultAction                        = $lowThreatDefaultAction
                MAPSReporting                                 = $mAPSReporting
                MeteredConnectionUpdates                      = $preferences.MeteredConnectionUpdates
                ModerateThreatDefaultAction                   = $moderateThreatDefaultAction
                PlatformUpdatesChannel                        = $platformUpdatesChannel
                ProxyBypass                                   = $proxyBypass
                ProxyPacUrl                                   = $proxyPacUrl
                ProxyServer                                   = $proxyServer
                PUAProtection                                 = $pUAProtection
                QuarantinePurgeItemsAfterDelay                = $quarantinePurgeItemsAfterDelay
                RandomizeScheduleTaskTimes                    = $preferences.RandomizeScheduleTaskTimes
                RealTimeScanDirection                         = $realTimeScanDirection
                RemediationScheduleDay                        = $remediationScheduleDay
                RemediationScheduleTime                       = $remediationScheduleTime
                ReportingAdditionalActionTimeOut              = $reportingAdditionalActionTimeOut
                ReportingCriticalFailureTimeOut               = $reportingCriticalFailureTimeOut
                ReportingNonCriticalTimeOut                   = $reportingNonCriticalTimeOut
                ScanAvgCPULoadFactor                          = $scanAvgCPULoadFactor
                ScanOnlyIfIdleEnabled                         = $preferences.ScanOnlyIfIdleEnabled
                ScanParameters                                = $scanParameters
                ScanPurgeItemsAfterDelay                      = $scanPurgeItemsAfterDelay
                ScanScheduleDay                               = $scanScheduleDay
                ScanScheduleOffset                            = $scanScheduleOffset
                ScanScheduleQuickScanTime                     = $scanScheduleQuickScanTime
                ScanScheduleTime                              = $scanScheduleTime
                SchedulerRandomizationTime                    = $preferences.SchedulerRandomizationTime
                ServiceHealthReportInterval                   = $preferences.ServiceHealthReportInterval
                SevereThreatDefaultAction                     = $severeThreatDefaultAction
                SharedSignaturesPath                          = $preferences.SharedSignaturesPath
                SubmitSamplesConsent                          = $submitSamplesConsent
                ThreatIDDefaultAction_Actions                 = $threatIDDefaultAction_Actions
                ThreatIDDefaultAction_Ids                     = $preferences.ThreatIDDefaultAction_Ids
                ThrottleForScheduledScanOnly                  = $preferences.ThrottleForScheduledScanOnly
                TrustLabelProtectionStatus                    = $preferences.TrustLabelProtectionStatus
                UILockdown                                    = $preferences.UILockdown
                UnknownThreatDefaultAction                    = $preferences.UnknownThreatDefaultAction
            }
        }
        catch {
            Write-Output "ERROR: Please check $(Join-Path -Path $ExportPath -ChildPath $ErrorLog) for more information"
            [PSCustomObject]$_ | Export-CSV -Path (Join-Path -Path $ExportPath -ChildPath $ErrorLog) -Encoding UTF8 -Force -NoTypeInformation -ErrorAction Stop
            return
        }
        try {
            $antimalwareStatus = Get-MpComputerStatus -ErrorAction Stop

            $avResults = [PSCustomObject]@{
                AMRunningMode                    = $antimalwareStatus.AMRunningMode
                AMServiceEnabled                 = $antimalwareStatus.AMServiceEnabled
                AntispywareEnabled               = $antimalwareStatus.AntispywareEnabled
                AntivirusEnabled                 = $antimalwareStatus.AntivirusEnabled
                BehaviorMonitorEnabled           = $antimalwareStatus.BehaviorMonitorEnabled
                ComputerState                    = $antimalwareStatus.ComputerState
                DefenderSignaturesOutOfDate      = $antimalwareStatus.DefenderSignaturesOutOfDate
                DeviceControlDefaultEnforcement  = $antimalwareStatus.DeviceControlDefaultEnforcement
                DeviceControlPoliciesLastUpdated = $antimalwareStatus.DeviceControlPoliciesLastUpdated
                DeviceControlState               = $antimalwareStatus.DeviceControlState
                IsTamperProtected                = $antimalwareStatus.IsTamperProtected
                IsVirtualMachine                 = $antimalwareStatus.IsVirtualMachine
                NISEnabled                       = $antimalwareStatus.NISEnabled
                OnAccessProtectionEnabled        = $antimalwareStatus.OnAccessProtectionEnabled
                RealTimeProtectionEnabled        = $antimalwareStatus.RealTimeProtectionEnabled
                RealTimeScanDirection            = $antimalwareStatus.RealTimeScanDirection
                RebootRequired                   = $antimalwareStatus.RebootRequired
                TamperProtectionSource           = $antimalwareStatus.TamperProtectionSource
                TDTMode                          = $antimalwareStatus.TDTMode
                TDTStatus                        = $antimalwareStatus.TDTStatus
            }

            $sigResults = [PSCustomObject]@{
                AMEngineVersion                              = $antimalwareStatus.AMEngineVersion
                AMProductVersion                             = $antimalwareStatus.AMProductVersion
                AMServiceVersion                             = $antimalwareStatus.AMServiceVersion
                AntispywareSignatureAge                      = $antimalwareStatus.AntispywareSignatureAge
                AntispywareSignatureLastUpdated              = $antimalwareStatus.AntispywareSignatureLastUpdated
                AntispywareSignatureVersion                  = $antimalwareStatus.AntispywareSignatureVersion
                AntivirusSignatureAge                        = $antimalwareStatus.AntivirusSignatureAge
                AntivirusSignatureLastUpdated                = $antimalwareStatus.AntivirusSignatureLastUpdated
                AntivirusSignatureVersion                    = $antimalwareStatus.AntivirusSignatureVersion
                DefenderSignaturesOutOfDate                  = $antimalwareStatus.DefenderSignaturesOutOfDate
                NISEngineVersion                             = $antimalwareStatus.NISEngineVersion
                NISSignatureAge                              = $antimalwareStatus.NISSignatureAge
                NISSignatureLastUpdated                      = $antimalwareStatus.NISSignatureLastUpdated
                NISSignatureVersion                          = $antimalwareStatus.NISSignatureVersion
                QuickScanSignatureVersion                    = $antimalwareStatus.QuickScanSignatureVersion
                SignatureAuGracePeriod                       = $signatureAuGracePeriod
                SignatureBlobFileSharesSources               = $preferences.SignatureBlobFileSharesSources
                SignatureBlobUpdateInterval                  = $preferences.SignatureBlobUpdateInterval
                SignatureDefinitionUpdateFileSharesSources   = $preferences.SignatureDefinitionUpdateFileSharesSources
                SignatureDisableUpdateOnStartupWithoutEngine = $preferences.SignatureDisableUpdateOnStartupWithoutEngine
                SignatureFallbackOrder                       = $preferences.SignatureFallbackOrder
                SignatureFirstAuGracePeriod                  = $signatureFirstAuGracePeriod
                SignatureScheduleDay                         = $signatureScheduleDay
                SignatureScheduleTime                        = $preferences.SignatureScheduleTime
                SignatureUpdateCatchupInterval               = $signatureUpdateCatchupInterval
                SignatureUpdateInterval                      = $signatureUpdateInterval
            }

            $tamperResults = [PSCustomObject]@{
                CloudBlockLevel        = $cloudBlockLevel
                IsTamperProtected      = $antimalwareStatus.IsTamperProtected
                TamperProtectionSource = $antimalwareStatus.TamperProtectionSource
            }

            $scannerResults = [PSCustomObject]@{
                CheckForSignaturesBeforeRunningScan           = $preferences.CheckForSignaturesBeforeRunningScan
                DisableCatchupFullScan                        = $preferences.DisableCatchupFullScan
                DisableCatchupQuickScan                       = $preferences.DisableCatchupQuickScan
                DisableCpuThrottleOnIdleScans                 = $preferences.DisableCpuThrottleOnIdleScans
                DisableEmailScanning                          = $preferences.DisableEmailScanning
                DisableRemovableDriveScanning                 = $preferences.DisableRemovableDriveScanning
                DisableScanningMappedNetworkDrivesForFullScan = $preferences.DisableScanningMappedNetworkDrivesForFullScan
                DisableScanningNetworkFiles                   = $preferences.DisableScanningNetworkFiles
                EnableFullScanOnBatteryPower                  = $preferences.EnableFullScanOnBatteryPower
                QuickScanSignatureVersion                     = $antimalwareStatus.QuickScanSignatureVersion
                RealTimeScanDirection                         = $antimalwareStatus.RealTimeScanDirection
                ScanAvgCPULoadFactor                          = $scanAvgCPULoadFactor
                ScanOnlyIfIdleEnabled                         = $preferences.ScanOnlyIfIdleEnabled
                ScanParameters                                = $scanParameters
                ScanPurgeItemsAfterDelay                      = $scanPurgeItemsAfterDelay
                ScanScheduleDay                               = $scanScheduleDay
                ScanScheduleOffset                            = $scanScheduleOffset
                ScanScheduleQuickScanTime                     = $scanScheduleQuickScanTime
                ScanScheduleTime                              = $scanScheduleTime
                ThrottleForScheduledScanOnly                  = $preferences.ThrottleForScheduledScanOnly
            }
        }
        catch {
            Write-Output "ERROR: Please check $(Join-Path -Path $ExportPath -ChildPath $ErrorLog) for more information"
            [PSCustomObject]$_ | Export-CSV -Path (Join-Path -Path $ExportPath -ChildPath $ErrorLog) -Encoding UTF8 -Force -NoTypeInformation -ErrorAction Stop
            return
        }

        try {
            # If nothing was specified to be displayed then show everything by default
            if (-NOT($parameters.ContainsKey('DisplayAmSettings')) -and -NOT($parameters.ContainsKey('DisplaySignatureSettings'))`
                    -and -NOT($parameters.ContainsKey('DisplayWindowsDefenderSettings')) -and -NOT($parameters.ContainsKey('DisplayTamperProtectionSettings'))`
                    -and -NOT($parameters.ContainsKey('DisplayScannerSettings'))) {
                $avResults
                $sigResults
                $policyResults
            }

            # Allow the end user to select the results to be displayed by choice
            if ($parameters.ContainsKey('DisplayAmSettings')) {
                $antimalwareSettings
                '-' * $antimalwareSettings.Length
                $avResults
            }
            if ($parameters.ContainsKey('DisplayTamperProtectionSettings')) {
                $tamperProtectionSettings
                '-' * $tamperProtectionSettings.Length
                $tamperResults
            }
            if ($parameters.ContainsKey('DisplaySignatureSettings')) {
                $signatureSettings
                '-' * $signatureSettings.Length
                $sigResults
            }
            if ($parameters.ContainsKey('DisplayWindowsDefenderSettings')) {
                $windowsDefenderSettings
                '-' * $windowsDefenderSettings.Length
                $policyResults
            }

            if ($parameters.ContainsKey('DisplayScannerSettings')) {
                $windowsDefenderScannerSettings
                '-' * $windowsDefenderScannerSettings.length
                $scannerResults
            }
        }
        catch {
            Write-Output "ERROR: Please check $(Join-Path -Path $ExportPath -ChildPath $ErrorLog) for more information"
            Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ErrorLog) -InputObject $_ -Encoding UTF8 -NoTypeInformation -Force -ErrorAction Stop
            return
        }

        Remove-Module -Name ConfigDefender
    }

    end {
        if ($parameters.ContainsKey('SaveResults')) {
            try {
                Write-Output "Saving $(Join-Path -Path $ExportPath -ChildPath $MpExportFile)"
                Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $MpExportFile) -InputObject $policyResults -Encoding UTF8 -ErrorAction SilentlyContinue
                Write-Output "Saving $(Join-Path -Path $ExportPath -ChildPath $AmResultsExportFile)"
                Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $AmResultsExportFile) -InputObject $avResults -Encoding UTF8 -ErrorAction SilentlyContinue
                Write-Output "Saving $(Join-Path -Path $ExportPath -ChildPath $SignatureResultsExportFile)"
                Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $SignatureResultsExportFile) -InputObject $sigResults -Encoding UTF8 -ErrorAction SilentlyContinue
            }
            catch {
                Write-Output "ERROR: Please check $(Join-Path -Path $ExportPath -ChildPath $ErrorLog) for more information"
                Out-File -FilePath (Join-Path -Path $ExportPath -ChildPath $ErrorLog) -InputObject $_ -Encoding UTF8 -NoTypeInformation -Force -ErrorAction Stop
                return
            }
        }
    }
}