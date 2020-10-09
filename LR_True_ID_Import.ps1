# ###########################################
#
# LogRhythm Identities from Active Directory
# LR_True_ID_Import.ps1
#
# ###############
#
# (c) 2020, LogRhythm
#
# ###############
#
# Change Log:
#
# v1.0 - 2020-10-09 - Tony Massé (tony.masse@logrhythm.com)
# - Turn Debug and Verbose off
#
# v0.5 - 2020-10-09 - Tony Massé (tony.masse@logrhythm.com)
# - Better logging
# - Catch and logs when API call cause error
#
# v0.4 - 2020-10-08 - Tony Massé (tony.masse@logrhythm.com)
# - Disable dead Identities
# - Enable disabled Identities
#
# v0.3 - 2020-10-07 - Tony Massé (tony.masse@logrhythm.com)
# - Add new Identities
#
# v0.2 - 2020-10-07 - Tony Massé (tony.masse@logrhythm.com)
# - Prompt user for configuration
# - Save Config file
# - load Config file
# - Logging
# - Error handling
#
# v0.1 - 2020-10-07 - Tony Massé (tony.masse@logrhythm.com)
# - Pulling A/D users from CSV file
# - Pulling LogRhythm Identities from Cloud or Appliance
#
# ################
#
# TO DO
#
# ################

# ###########################
# Declaring the parameters
# ###########################

param (
     [Parameter(Mandatory = $false, Position = 0)]
     [string]$CsvFileToImportFrom = 'AD-export.csv'

    ,[Parameter(Mandatory = $false, Position = 1)]
     [ValidateSet('AddNewOnesOnly', 'Synchronise', ignorecase=$true)]
     [string]$Action = 'Synchronise'

    ,[Parameter(Mandatory = $false, Position = 2)]
     [int]$EntityId = 0 # Defaulting to Global Entity

    ,[Parameter(Mandatory = $false, Position = 3)]
     [string]$SyncName = 'A/D => CSV => Identities Import'

    ,[Parameter(Mandatory = $false, Position = 3)]
     [switch]$CreateConfiguration = $false
)

# ###########################
# Import required Modules
# ###########################

if ((Get-Module -Name LogRhythm.Tools).Count -gt 0)
{
    Remove-Module -Name LogRhythm.Tools
}

if ((Get-Module -Name LogRhythm.Tools -ListAvailable).Count -gt 0)
{
    Import-Module LogRhythm.Tools
}
else
{
    Write-Warning 'Could not load module ''LogRhythm.Tools''. Exiting.'
    exit 20
}

# ###########################
# Declaring all the variables
# ###########################

# Version
$Version = "v1.0 - 2020-10-09 - Tony Masse (tony.masse@logrhythm.com)"

# Logging level
$Logginglevel = @{"INFO" = $true; # Default: True
                  "ERROR" = $true; # Default: True
                  "VERBOSE" = $false;  # Default: False
                  "DEBUG" = $false; # Default: False
                 }

$LoggingColors = @{"INFO" = "White"; # Default: "White"
                  "ERROR" = "Red"; # Default: "Red"
                  "VERBOSE" = "Cyan";  # Default: "Cyan"
                  "DEBUG" = "DarkGray"; # Default: "DarkGray"
                 }


# Directories and files information
# Base directory and Script name
$ScriptFileFullName = $MyInvocation.MyCommand.Path
$basePath = Split-Path $ScriptFileFullName
$ScriptFileName = $MyInvocation.MyCommand.Name

cd $basePath

# Config directory and file
$configPath = Join-Path -Path $basePath -ChildPath "config"
if (-Not (Test-Path $configPath))
{
	New-Item -ItemType directory -Path $configPath | out-null
}

$configFile = Join-Path -Path $configPath -ChildPath "config.json"

# Log directory and file
$logsPath = Join-Path -Path $basePath -ChildPath "logs"
if (-Not (Test-Path $logsPath))
{
	New-Item -ItemType directory -Path $logsPath | out-null
}

# For the Diagnostics (logs from this script)
$logFileBaseName = "LogRhythm.TrueIdentitiesSync."
$logFile = Join-Path -Path $logsPath -ChildPath ($logFileBaseName + (Get-Date).tostring("yyyyMMdd") + ".log")
if (-Not (Test-Path $logFile))
{
	New-Item $logFile -type file | out-null
}

# ###########################
# Declaring all the functions
# ###########################


# #################
# Logging functions
function Log-Message
{
    param
    (
        [string] $logLevel = "INFO",
        [string] $message,
        [Switch] $NotToFile = $False,
        [Switch] $NotToConsole = $False,
        [Switch] $NotToLogFile = $False,
        [Switch] $RAW = $False
    )

    if ($Logginglevel."$logLevel")
        {

        if ($RAW)
        {
            $Msg  = $message
        }
        else
        {
            $Msg  = ([string]::Format("{0}|{1}|{2}", (Get-Date).tostring("yyyy.MM.dd HH:mm:ss"), $logLevel, $message))
        }

	    if (-not($NotToFile)) 
        {
    	    if (-not($NotToLogFile))  { $Msg | Out-File -FilePath $logFile  -Append }
        }
        if (-not($NotToConsole)) { Write-Host $Msg -ForegroundColor $LoggingColors."$logLevel" }
    }
}

function Log-Info
{
    param
    (
        [string] $message,
        [Switch] $NotToFile = $False,
        [Switch] $NotToConsole = $False,
        [Switch] $NotToLogFile = $False
    )
    Log-Message -logLevel "INFO" @PSBoundParameters
}

function Log-Verbose
{
    param
    (
        [string] $message,
        [Switch] $NotToFile = $False,
        [Switch] $NotToConsole = $False,
        [Switch] $NotToLogFile = $False
    )
    Log-Message -logLevel "VERBOSE" @PSBoundParameters
}

function Log-Error
{
    param
    (
        [string] $message,
        [Switch] $NotToFile = $False,
        [Switch] $NotToConsole = $False,
        [Switch] $NotToLogFile = $False
    )
    Log-Message -logLevel "ERROR" @PSBoundParameters
}

function Log-Debug
{
    param
    (
        [string] $message,
        [Switch] $NotToFile = $False,
        [Switch] $NotToConsole = $False,
        [Switch] $NotToLogFile = $False
    )
    Log-Message -logLevel "DEBUG" @PSBoundParameters
}

function Prompt-User
{
	param( 
		[string] [Parameter(Mandatory=$true)] $Prompt
		,[string] [Parameter(Mandatory=$false)] $PopupTitle = ''
		,[string] [Parameter(Mandatory=$false)] $DefaultValue = ''
		,[string[]] [Parameter(Mandatory=$false)] $ValueOptions = @()
		,[switch] [Parameter(Mandatory=$false)] $UseTextOnly = $false
		,[switch] [Parameter(Mandatory=$false)] $CaseInsensitive = $false
		,[switch] [Parameter(Mandatory=$false)] $DoNotTrim = $false
		,[switch] [Parameter(Mandatory=$false)] $SecureString = $false
		,[switch] [Parameter(Mandatory=$false)] $ReturnAsEncryptedString = $false
		,[switch] [Parameter(Mandatory=$false)] $ReturnAsPlainString = $false

	)

    if ($SecureString)
    {
        $UseTextOnly = $true
    }

    if (-Not $UseTextOnly)
    {
        try
        {
            Add-Type -AssemblyName Microsoft.VisualBasic
        }
        catch
        {
            $UseTextOnly = $true
        }
    }

    # Prepare the Options
    $OptionsText = ''
    if ($ValueOptions.length -gt 0)
    {
        if ($UseTextOnly)
        {
            $OptionsText += ' ( Options: '
            $Separator = ''
	        ForEach ($ValueOption in $ValueOptions) {
                $OptionsText += $Separator + $ValueOption
                $Separator = ' / '
   	        }
            if ($DefaultValue -ne '')
            {
                $OptionsText += $Separator + 'or press [Enter] to keep current value of "' + $DefaultValue + '"'
            }
            $OptionsText += ' )'
        }
        else
        {
            $OptionsText += "`n`nOptions:"
	        ForEach ($ValueOption in $ValueOptions) {
                $OptionsText += "`n - " + $ValueOption
   	        }
        }
    }
    else
    {
        if ($DefaultValue -ne '')
        {
            $OptionsText += ' ( or press [Enter] to keep current value of "' + $DefaultValue + '" )'
        }
    }

    # Prompt the user
    if ($UseTextOnly)
    {
        # If a title was provided, add a separator between it and the Prompt itself
        $TitleSeparator = ''
        if ($PopupTitle -ne '')
        {
            $TitleSeparator = ' | '
        }
        if ($SecureString)
        {
            $input = $( Read-Host ($PopupTitle + $TitleSeparator + $Prompt + $OptionsText) -AsSecureString )
        }
        else
        {
            $input = $( Read-Host ($PopupTitle + $TitleSeparator + $Prompt + $OptionsText) )
        }
        if ($DefaultValue -ne '' -And $input -eq '')
        {
            $input = $DefaultValue
        }
    }
    else
    {
        if ($PopupTitle -eq '')
        {
            $PopupTitle = ' ' # To prevent the ugly "Anonymously Hosted DynamicMethods Assembly" auto generated Pop-up Title :)
        }
        $input = $( [Microsoft.VisualBasic.Interaction]::InputBox($Prompt + $OptionsText, $PopupTitle, $DefaultValue) )
    }

    if ($SecureString)
    {
        if ($ReturnAsEncryptedString)
        {
            $input = ConvertFrom-SecureString -SecureString $input
        }
        elseif ($ReturnAsPlainString)
        {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($input) 
            $input = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $BSTR = $null
        }
    }
    else
    {
        # Bring it to Lower Case
        if ($CaseInsensitive)
        {
            $input = $input.ToLower()
        }

        # Trim (both ends), unless asked not to
        if (-Not $DoNotTrim)
        {
            $input = $input.Trim()
        }
    }
    return $input
}

function StringToBool
{
	param( 
		[string] [Parameter(Mandatory=$true)] $String
	)

    try
    {
        if ($String.substring(0, 1).ToUpper() -eq 'Y')
        {
            return $true
        }
    }
    catch
    {
    }

    return $false
}

# ################################################
# ################################################
# ################################################


# ################################################
# Starting LogRhythm Identities from Active Directory

Log-Info -message "Starting LogRhythm Identities from Active Directory"
Log-Info "Version: ", $Version


# ###################
# Reading config file
if (-Not (Test-Path $configFile))
{
    if ($CreateConfiguration)
    {
	    Log-Info "File 'config.json' doesn't exists. Starting with fresh config"
    }
    else
    {
	    Log-Error "File 'config.json' doesn't exists. Exiting"
	    return
    }
}
else
{
    Log-Info "File 'config.json' exists."
}

try
{
    if (-Not (Test-Path $configFile) -and $CreateConfiguration)
    {
        $configJson = @{}
    }
    else
    {
	    $configJson = Get-Content -Raw -Path $configFile | ConvertFrom-Json
    }
	ForEach ($attribute in @("Configuration Generated", "KeepOldLogFilesForDays")) {
		if (-Not (Get-Member -inputobject $configJson -name $attribute -Membertype Properties) -Or [string]::IsNullOrEmpty($configJson.$attribute))
		{
            if ((-Not $CreateConfiguration) -and ($attribute -ne "Configuration Generated"))
            {
			    Log-Error ($attribute + " has not been specified in 'config.json' file. Exiting")
			    return
            }
            else
            {
                try
                {
                    $configJson | Add-Member -NotePropertyName $attribute -NotePropertyValue @{}


                    if ($attribute -eq 'KeepOldLogFilesForDays')
                    {
                        $configJson.KeepOldLogFilesForDays = [int] (Prompt-User -Prompt "How many days to you want to keep the diagnostic logs of this tool?" -DefaultValue '35' -PopupTitle ("Configuration: {0}" -f $attribute))
                    }
                    # ####################
                    # Save the file so far
                    try
                    {
                        $configJson.'Configuration Generated' = @{"By" = ("LogRhythm Identities from Active Directory - Version {0}" -f $Version)
                                                                ; "Automatically" = $true
                                                                ; "At" = (Get-Date).tostring("yyyy.MM.dd HH:mm:ss zzz")
                                                                ; "For" = ("LogRhythm Identities from Active Directory - Version {0}" -f $Version)
                                                                ; "By User" = $env:USERNAME }

                        Log-Info "Saving to 'config.json' file..."
                        if (-Not (Test-Path $configFile))
                        {
                            Log-Info "File 'config.json' doesn't exist. Creating it..."
	                        New-Item $configFile -type file | out-null
                        }
                        # Write the Config into the Config file
                        $configJson | ConvertTo-Json -Depth 5 | Out-File -FilePath $configFile     
                        Log-Info "Configuration saved."
                    }
                    catch
                    {
                        Log-Error ("Failed to save config.json. Reason: {0}" -f $Error[0])
                    }

                }
                catch
                {
                	Log-Error ("Could not add branch {0} to the configuration. Skipping. Reason: {1}" -f $attribute, $Error[0])
                }

            }
		}
	}
    Log-Info "File 'config.json' parsed correctly."
}
catch
{
	Log-Error ("Could not parse 'config.json' file. Exiting. Reason: {0}" -f $Error[0])
	return
}

if ($CreateConfiguration)
{
    # Job done. Leaving you now.
    return
}


# ###################################
# Delete Log files older than X days.
# Limit to at least 0 days, and maximum 1 year + 1 day
try
{
    if ($configJson.KeepOldLogFilesForDays -lt 0) { $configJson.KeepOldLogFilesForDays = 0 }
    if ($configJson.KeepOldLogFilesForDays -gt 366) { $configJson.KeepOldLogFilesForDays = 366 }
	Log-Info ("Delete Log files older than {0} days..." -f $configJson.KeepOldLogFilesForDays.ToString("D"))
    Get-ChildItem -Path $logsPath -include ($logFileBaseName + "*") | Where-Object { !$_.PSIsContainer -and $_.LastWriteTime -lt (Get-Date).AddDays(-$configJson.KeepOldLogFilesForDays) } | Remove-Item
}
catch
{
	Log-Error ("Failed to delete old log files. Reason: {0}" -f $Error[0])
}



# ###################################
# Load new Active Directory users from the CSV export
Log-Info 'Load current Active Directory users from the CSV'
try
{
    $ADUsersFromCsv = Import-Csv -Path $CsvFileToImportFrom
}
catch
{
    Log-Error ("Failed to fetch Active Directory users from CSV. Reason: {0}" -f $Error[0])
}
Log-Info ("Number of Users found: {0}" -f $ADUsersFromCsv.Count)


# ###################################
# Load current Entities from the Cloud
Log-Info 'Load current Entities from the Cloud or Appliance'
try
{
    $IdentitiesFromCloud = Get-LrIdentities
}
catch
{
    Log-Error ("Failed to fetch Identities from LogRhythm. Reason: {0}" -f $Error[0])
}
Log-Info ("Number of Identities found: {0}" -f $IdentitiesFromCloud.Count)

# ###################################
# Prepare arrays for Delta between CSV and Cloud lists

Log-Info 'Users from CSV: Compile values into simple list'
$ADUsersIDListFromCsv = New-Object System.Collections.ArrayList
try
{
    $ADUsersFromCsv | ForEach-Object {
        if ($_.UserPrincipalName -ne $null)
        {
            $ADUsersIDListFromCsv.Add($_.UserPrincipalName.ToLower()) > $null
        }
    }

}
catch
{
    Log-Error ("Failed to compile Identities' values. Reason: {0}" -f $Error[0])
}


Log-Info 'Identities from Cloud: Compile values into simple list'
$IdentityIDListFromCloud = New-Object System.Collections.ArrayList
try
{
    $IdentitiesFromCloud | ForEach-Object {
        if ($_.displayIdentifier -ne $null)
        {
            $IdentityIDListFromCloud.Add($_.displayIdentifier.ToLower()) > $null
        }
    }

}
catch
{
    Log-Error ("Failed to compile Identities' values. Reason: {0}" -f $Error[0])
}


$DoingNothing = $false
$ActionAddNewOnesOnly = $false
$ActionSynchronise = $false

switch ($Action.ToUpper()) { 
    ("AddNewOnesOnly").ToUpper() {
        Log-Info 'A/D Users => Identities - Adding only new Users to Identities'
        $ActionAddNewOnesOnly = $true
        break
    }
    ("Synchronise").ToUpper() {
        Log-Info 'A/D Users => Identities - Synchronise Identities to Users (Disable non-provided Users and Add new ones)'
        $ActionSynchronise = $true
        break
    }
    default {
        Log-Error "Unknown Action: ""$Action"". Doing nothing."
        $DoingNothing = $true
        break
    }
}


$ItemsAdded = 0
$ItemsDisabled = 0
$ItemsUpdated = 0

if (-Not $DoingNothing)
{
    # ###################################
    # Temporary array to store the Identifiers of the Identity
    $Identifiers = New-Object System.Collections.ArrayList
    
    try
    {
        if ($ActionAddNewOnesOnly) {
            Write-Host "Adding items: " -NoNewline
        }

        if ($ActionSynchronise) {
            Write-Host "Syncing items: " -NoNewline
        }

        # Go through the AD Users to Add or Update
        ForEach ($ADUser in $ADUsersFromCsv) {
            # Bring the UserPrincipalName to lowercase
            $UserPrincipalName = ''
            if ($ADUser.UserPrincipalName -ne $null) {
                $UserPrincipalName = $ADUser.UserPrincipalName.ToLower()
            }
            Log-Verbose ("Processing user with UserPrincipalName: ""{0}""..." -f $UserPrincipalName)

            # Check the identifiers for user need to be collected
            if ($ActionSynchronise `
                -Or ($ActionAddNewOnesOnly -And ($UserPrincipalName -notin $IdentityIDListFromCloud)))
            {
                # Build the list of identifiers
                if ($null -ne $($ADUser.SAMAccountName) -And $($ADUser.SAMAccountName -ne "")) {
                    $Identifiers.Add(@{ 'type' = 'login' ; 'value' = $ADUser.SAMAccountName }) > $null
                }

                if ($null -ne $($ADUser.UserPrincipalName) -And $($ADUser.UserPrincipalName -ne "")) {
                    $Identifiers.Add(@{ 'type' = 'both' ; 'value' = $ADUser.UserPrincipalName }) > $null
                }

                if ($null -ne $($ADUser.mail) -And $($ADUser.mail -ne "")) {
                    $Identifiers.Add(@{ 'type' = 'email' ; 'value' = $ADUser.mail }) > $null
                }

            } # if ($ActionSynchronise `
              # -Or ($ActionAddNewOnesOnly -And ($UserPrincipalName -notin $IdentityIDListFromCloud)))

            # ###############################
            # Add new Users to identities
            $Result = $null
            try
            {
                if (($ActionAddNewOnesOnly -Or $ActionSynchronise) -And ($UserPrincipalName -notin $IdentityIDListFromCloud)) {
                    switch ($Identifiers.Count) {
                        1 {
                            $Result = Add-LrIdentity -EntityId $EntityId -NameFirst $ADUser.givenName -NameLast $ADUser.sn -DisplayIdentifier $ADUser.UserPrincipalName -Department $ADUser.department -Company $ADUser.company -Title $ADUser.title -SyncName $SyncName -Identifier1Type $Identifiers[0].type -Identifier1Value $Identifiers[0].value
                            Log-Verbose ("Add-LrIdentity - {0} (with {1} identifiers)" -f $ADUser.Name, $Identifiers.Count)
                            Write-Host "+" -NoNewline -ForegroundColor Green
                            $ItemsAdded++
                            break
                        }

                        2 {
                            $Result = Add-LrIdentity -EntityId $EntityId -NameFirst $ADUser.givenName -NameLast $ADUser.sn -DisplayIdentifier $ADUser.UserPrincipalName -Department $ADUser.department -Company $ADUser.company -Title $ADUser.title -SyncName $SyncName -Identifier1Type $Identifiers[0].type -Identifier1Value $Identifiers[0].value -Identifier2Type $Identifiers[1].type -Identifier2Value $Identifiers[1].value
                            Log-Verbose ("Add-LrIdentity - {0} (with {1} identifiers)" -f $ADUser.Name, $Identifiers.Count)
                            Write-Host "+" -NoNewline -ForegroundColor Green
                            $ItemsAdded++
                            break
                        }

                        3 {
                            $Result = Add-LrIdentity -EntityId $EntityId -NameFirst $ADUser.givenName -NameLast $ADUser.sn -DisplayIdentifier $ADUser.UserPrincipalName -Department $ADUser.department -Company $ADUser.company -Title $ADUser.title -SyncName $SyncName -Identifier1Type $Identifiers[0].type -Identifier1Value $Identifiers[0].value -Identifier2Type $Identifiers[1].type -Identifier2Value $Identifiers[1].value -Identifier3Type $Identifiers[2].type -Identifier3Value $Identifiers[2].value
                            Log-Verbose ("Add-LrIdentity - {0} (with {1} identifiers)" -f $ADUser.Name, $Identifiers.Count)
                            Write-Host "+" -NoNewline -ForegroundColor Green
                            $ItemsAdded++
                            break
                        }

                        4 {
                            $Result = Add-LrIdentity -EntityId $EntityId -NameFirst $ADUser.givenName -NameLast $ADUser.sn -DisplayIdentifier $ADUser.UserPrincipalName -Department $ADUser.department -Company $ADUser.company -Title $ADUser.title -SyncName $SyncName -Identifier1Type $Identifiers[0].type -Identifier1Value $Identifiers[0].value -Identifier2Type $Identifiers[1].type -Identifier2Value $Identifiers[1].value -Identifier3Type $Identifiers[2].type -Identifier3Value $Identifiers[2].value -Identifier4Type $Identifiers[3].type -Identifier4Value $Identifiers[3].value
                            Log-Verbose ("Add-LrIdentity - {0} (with {1} identifiers)" -f $ADUser.Name, $Identifiers.Count)
                            Write-Host "+" -NoNewline -ForegroundColor Green
                            $ItemsAdded++
                            break
                        }

                        5 {
                            $Result = Add-LrIdentity -EntityId $EntityId -NameFirst $ADUser.givenName -NameLast $ADUser.sn -DisplayIdentifier $ADUser.UserPrincipalName -Department $ADUser.department -Company $ADUser.company -Title $ADUser.title -SyncName $SyncName -Identifier1Type $Identifiers[0].type -Identifier1Value $Identifiers[0].value -Identifier2Type $Identifiers[1].type -Identifier2Value $Identifiers[1].value -Identifier3Type $Identifiers[2].type -Identifier3Value $Identifiers[2].value -Identifier4Type $Identifiers[3].type -Identifier4Value $Identifiers[3].value -Identifier5Type $Identifiers[4].type -Identifier5Value $Identifiers[4].value
                            Log-Verbose ("Add-LrIdentity - {0} (with {1} identifiers)" -f $ADUser.Name, $Identifiers.Count)
                            Write-Host "+" -NoNewline -ForegroundColor Green
                            $ItemsAdded++
                            break
                        }

                        default {
                            Log-Error ("Wrong number of indentifiers ({0}) for user: ""{1}"". Doing nothing." -f $Identifiers.Count, $ADUser.UserPrincipalName)
                            break
                        }
                    } # switch ($Identifiers.Count) {
                } # if ($ActionAddNewOnesOnly) {
            }
            catch
            {
                Log-Error ("Failed to add Identity for user: ""{0}"". Reason: {1}" -f $ADUser.UserPrincipalName, $Error[0])
            }

            if ($Result -ne $null) {
                if ($Result -is [System.String]) {
                    Log-Error $Result
                }
                else
                {
                    Log-Verbose $Result
                }
                $Result = $null
            }

            # ###############################
            # Syncronise Users and Identities: Enable previously disabled ones
            try
            {
                if ($ActionSynchronise) {
                    # Get the Identity of the User, if any (set to $null otherwise)
                    $IdentitytoSync = $null
                    $IdentitiesFromCloud | ForEach-Object {
                        if ($_.displayIdentifier -ne $null) {
                            if ($_.displayIdentifier.ToLower() -in $ADUsersIDListFromCsv) {
                                # Keeper!
                                $IdentitytoSync = $_
                                # Save some cycles by leaving as soon as we've got our Identity found
                                break
                            }
                        }
                    }

                    # Check if user's identity is disabled. Action: enable the related identity
                    if ($IdentitytoSync.recordStatus -ne 'Active') {
                        # Enable Identity
                        $Result = Enable-LrIdentity -IdentityId $IdentitytoSync.identityID
                    }


                    # Check if user has same identifiers. Action: add/enable new Identifiers and disable old ones
                } # if ($ActionSynchronise) {
            }
            catch
            {
                Log-Error ("Failed to sync Identity for user: ""{0}"". Reason: {1}" -f $ADUser.UserPrincipalName, $Error[0])
            }

            if ($Result -ne $null) {
                if ($Result -is [System.String]) {
                    Log-Error $Result
                }
                else
                {
                    Log-Verbose $Result
                }
                $Result = $null
            }

            $Identifiers.Clear()

            if ((($ItemsAdded + $ItemsUpdated) -gt 0) -And (($ItemsAdded + $ItemsUpdated) % 100 -eq 0))
            {
                Write-Host ""
                Write-Host ("({0}) " -f ($ItemsAdded + $ItemsUpdated)) -NoNewline
            }
        } # ForEach ($ADUser in $ADUsersFromCsv) {
        $ADUser = $null

        
        # ###############################
        # Syncronise Users and Identities: Disable the missing ones
        
        # Go through the Identities to weed out / Disable the missing ones
        if ($ActionSynchronise)
        {
            ForEach ($Identity in $IdentitiesFromCloud) {
                # Bring the displayIdentifier to lowercase
                $displayIdentifier = ''
                if ($Identity.displayIdentifier -ne $null) {
                    $displayIdentifier = $Identity.displayIdentifier.ToLower()
                }
                Log-Verbose ("Processing identity with displayIdentifier: ""{0}""..." -f $displayIdentifier)

                # Check the identity needs weeding out / disabling
                if ($displayIdentifier -notin $ADUsersIDListFromCsv)
                {
                    try
                    {
                        $Response = Disable-LrIdentity -IdentityId $Identity.identityID
                        Write-Host "-" -NoNewline -ForegroundColor Red
                        $ItemsDisabled++
                    }
                    catch
                    {
                        Log-Error ("Failed to disable Identity with displayIdentifier: ""{0}"". Reason: {1}" -f $displayIdentifier, $Error[0])
                    }
                    
                    if ($Result -ne $null) {
                        if ($Result -is [System.String]) {
                            Log-Error $Result
                        }
                        else
                        {
                            Log-Verbose $Result
                        }
                        $Result = $null
                    }

                    if (($ItemsDisabled -gt 0) -And ($ItemsDisabled % 100 -eq 0))
                    {
                        Write-Host ""
                        Write-Host ("({0}) " -f $ItemsDisabled) -NoNewline
                    }
                } # if ($displayIdentifier -notin $ADUsersIDListFromCsv)
            } # ForEach ($Identity in $IdentitiesFromCloud) {
            $Identity = $null
        } # if ($ActionSynchronise)


    }
    catch
    {
        Log-Error ("Failed to add or update or disable Identities to LogRhythm's List. Reason: {0}" -f $Error[0])
    }
    Write-Host ""

} # if (-Not $DoingNothing)

Log-Info 'DONE'
Log-Info ("Summary - Identities Added to Cloud/Appliance: {0}" -f $ItemsAdded)
Log-Info ("Summary - Identities Updated on Cloud/Appliance: {0}" -f $ItemsUpdated)
Log-Info ("Summary - Identities Disabled on Cloud/Appliance: {0}" -f $ItemsDisabled)
