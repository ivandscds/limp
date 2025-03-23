cmd /c "cleanmgr /sageset:1 & cleanmgr /sagerun:1"
Remove-Item -Path "$env:TEMP\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Temp\*" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\Prefetch\*" -Force -ErrorAction SilentlyContinue
powercfg -h off
wmic computersystem where name="%computername%" set AutomaticManagedPagefile=False
wmic pagefileset where name="C:\\pagefile.sys" delete
Stop-Service -Name wuauserv, bits, cryptSvc, msiserver -Force -ErrorAction SilentlyContinue
Remove-Item -Path "C:\Windows\SoftwareDistribution" -Recurse -Force -ErrorAction SilentlyContinue
Start-Service -Name wuauserv, bits, cryptSvc, msiserver -ErrorAction SilentlyContinue
vssadmin delete shadows /all /quiet
Dism.exe /online /Cleanup-Image /StartComponentCleanup
compact.exe /c c:\*.* /s /i /exe:lzx
$appxPackages = @(
    "Microsoft.Microsoft3DViewer",
    "Microsoft.AppConnector",
    "Microsoft.BingFinance",
    "Microsoft.BingNews",
    "Microsoft.BingSports",
    "Microsoft.BingTranslator",
    "Microsoft.BingWeather",
    "Microsoft.BingFoodAndDrink",
    "Microsoft.BingHealthAndFitness",
    "Microsoft.BingTravel",
    "Microsoft.MinecraftUWP",
    "Microsoft.GamingServices",
    "Microsoft.GetHelp",
    "Microsoft.Getstarted",
    "Microsoft.Messaging",
    "Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftSolitaireCollection",
    "Microsoft.NetworkSpeedTest",
    "Microsoft.News",
    "Microsoft.Office.Lens",
    "Microsoft.Office.Sway",
    "Microsoft.Office.OneNote",
    "Microsoft.OneConnect",
    "Microsoft.People",
    "Microsoft.Print3D",
    "Microsoft.SkypeApp",
    "Microsoft.Wallet",
    "Microsoft.Whiteboard",
    "microsoft.windowscommunicationsapps",
    "Microsoft.WindowsFeedbackHub",
    "Microsoft.WindowsMaps",
    "Microsoft.YourPhone",
    "Microsoft.WindowsSoundRecorder",
    "Microsoft.XboxApp",
    "Microsoft.ConnectivityStore",
    "Microsoft.ScreenSketch",
    "Microsoft.Xbox.TCUI",
    "Microsoft.XboxGameOverlay",
    "Microsoft.XboxGameCallableUI",
    "Microsoft.XboxSpeechToTextOverlay",
    "Microsoft.MixedReality.Portal",
    "Microsoft.XboxIdentityProvider",
    "Microsoft.ZuneMusic",
    "Microsoft.ZuneVideo",
    "Microsoft.Getstarted",
    "Microsoft.MicrosoftOfficeHub",
    "*EclipseManager*",
    "*ActiproSoftwareLLC*",
    "*AdobeSystemsIncorporated.AdobePhotoshopExpress*",
    "*Duolingo-LearnLanguagesforFree*",
    "*PandoraMediaInc*",
    "*CandyCrush*",
    "*BubbleWitch3Saga*",
    "*Wunderlist*",
    "*Flipboard*",
    "*Twitter*",
    "*Facebook*",
    "*Royal Revolt*",
    "*Sway*",
    "*Speed Test*",
    "*Dolby*",
    "*Viber*",
    "*ACGMediaPlayer*",
    "*Netflix*",
    "*OneCalendar*",
    "*LinkedInforWindows*",
    "*HiddenCityMysteryofShadows*",
    "*Hulu*",
    "*HiddenCity*",
    "*AdobePhotoshopExpress*",
    "*HotspotShieldFreeVPN*",
    "*Microsoft.Advertising.Xaml*"
)
foreach ($package in $appxPackages) {
    try {
        Get-AppxPackage $package | Remove-AppxPackage -ErrorAction Stop
    }
    catch {
    }
}
try {
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" -Name "GlobalUserDisabled" -Value 1 -Type DWord -ErrorAction Stop
}
catch {
}
Function Uninstall-WinUtilEdgeBrowser {
    $msedgeProcess = Get-Process -Name "msedge" -ErrorAction SilentlyContinue
    $widgetsProcess = Get-Process -Name "widgets" -ErrorAction SilentlyContinue
    if ($msedgeProcess) { Stop-Process -Name "msedge" -Force }
    if ($widgetsProcess) { Stop-Process -Name "widgets" -Force }
    function Uninstall-Process {
        param ([Parameter(Mandatory = $true)][string]$Key)
        $originalNation = [microsoft.win32.registry]::GetValue('HKEY_USERS\.DEFAULT\Control Panel\International\Geo', 'Nation', [Microsoft.Win32.RegistryValueKind]::String)
        [microsoft.win32.registry]::SetValue('HKEY_USERS\.DEFAULT\Control Panel\International\Geo', 'Nation', 68, [Microsoft.Win32.RegistryValueKind]::String) | Out-Null
        $fileName = "IntegratedServicesRegionPolicySet.json"
        $pathISRPS = [Environment]::SystemDirectory + "\" + $fileName
        $aclISRPS = Get-Acl -Path $pathISRPS
        $aclISRPSBackup = [System.Security.AccessControl.FileSecurity]::new()
        $aclISRPSBackup.SetSecurityDescriptorSddlForm($aclISRPS.Sddl)
        if (Test-Path -Path $pathISRPS) {
            try {
                <span class="math-inline">admin \= \[System\.Security\.Principal\.NTAccount\]</span>(New-Object System.Security.Principal.SecurityIdentifier('S-1-5-32-544')).Translate([System.Security.Principal.NTAccount]).Value
                $aclISRPS.SetOwner($admin)
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule($admin, 'FullControl', 'Allow')
                $aclISRPS.AddAccessRule($rule)
                Set-Acl -Path $pathISRPS -AclObject $aclISRPS
                Rename-Item -Path $pathISRPS -NewName ($fileName + '.bak') -Force
            }
            catch { }
        }
        $baseKey = 'HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate'
        $registryPath = $baseKey + '\ClientState\' + $Key
        if (!(Test-Path -Path $registryPath)) { return }
        Remove-ItemProperty -Path $registryPath -Name "experiment_control_labels" -ErrorAction SilentlyContinue | Out-Null
        $uninstallString = (Get-ItemProperty -Path $registryPath).UninstallString
        $uninstallArguments = (Get-ItemProperty -Path $registryPath).UninstallArguments
        if ([string]::IsNullOrEmpty($uninstallString) -or [string]::IsNullOrEmpty($uninstallArguments)) { return }
        $uninstallArguments += " --force-uninstall --delete-profile"
        if (!(Test-Path -Path $uninstallString)) { return }
        Start-Process -FilePath $uninstallString -ArgumentList $uninstallArguments -Wait -NoNewWindow -Verbose
        if (Test-Path -Path ($pathISRPS + '.bak')) {
            Rename-Item -Path ($pathISRPS + '.bak') -NewName $fileName -Force
            Set-Acl -Path $pathISRPS -AclObject $aclISRPSBackup
        }
        [microsoft.win32.registry]::SetValue('HKEY_USERS\.DEFAULT\Control Panel\International\Geo', 'Nation', $originalNation, [Microsoft.Win32.RegistryValueKind]::String) | Out-Null
    }
    function Uninstall-Edge {
        Remove-ItemProperty -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge" -Name "NoRemove" -ErrorAction SilentlyContinue | Out-Null
        [microsoft.win32.registry]::SetValue("HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdateDev", "AllowUninstall", 1, [Microsoft.win32.RegistryValueKind]::DWord) | Out-Null
        Uninstall-Process -Key '{56EB18F8-B008-4CBD-B6D2-8C97FE7E9062}'
        @( "$env:ProgramData\Microsoft\Windows\Start Menu\Programs", "$env:PUBLIC\Desktop", "$env:USERPROFILE\Desktop" ) | ForEach-Object {
            $shortcutPath = Join-Path -Path $_ -ChildPath "Microsoft Edge.lnk"
            if (Test-Path -Path $shortcutPath) { Remove-Item -Path $shortcutPath -Force }
        }
    }
    function Uninstall-WebView {
        Remove-Item -Path "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft EdgeWebView" -Name "NoRemove" -ErrorAction SilentlyContinue | Out-Null
        Uninstall-Process -Key '{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}'
    }
    Uninstall-Edge
}
Uninstall-WinUtilEdgeBrowser
Write-Host "Proceso finalizado."
