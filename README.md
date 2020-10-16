# LogRhythm-True-ID-Import
 Script to import users from CSV into **LogRhythm True Identity**.

Works for both LogRhythm On-Prem (Appliance and Software deployments) and LogRhythm Cloud customers.

## Kick-start:

`.\LR_True_ID_Import.ps1 -CreateConfiguration`

`.\LR_True_ID_Import.ps1 -EntityId 1 -Action AddNewOnesOnly -SyncName "My Sync Job Name" -CsvFileToImportFrom MyExportFile.csv`

## Dependencies

This requires:
- [Logrhythm.Tools](https://github.com/LogRhythm-Tools/LogRhythm.Tools)
	- Publishers: some cool LogRhythm enthusiasts
	- Releases: https://github.com/LogRhythm-Tools/LogRhythm.Tools/releases
	- :exclamation: At the time of publishing (2020-10-16), it's best to use my Forked version of the LogRhythm.Tools, as it provides a few required features for this script to work (`Title` for Identities and properly unique `VendorUniqueKey`)
		- Pick at least version 1.0.1.3^
			- [v1.0.1.3 - Release Candidate - Proxy Aware and Identity Title and VendorUniqueKey](https://github.com/TonyMasse/LogRhythm.Tools/releases/tag/v1.0.1.3-rc-proxy-title-vendoruniquekey)

## Usage examples:

- To create the Configuration file:

`.\LR_True_ID_Import.ps1 -CreateConfiguration`

- To synchronise all your existing user Identities with the ones in the `AD-export.csv` CSV file. Using default `EntityID` *`0`* (**Global Entity**) and `SyncName` *`A/D => CSV => Identities Import`*

`.\LR_True_ID_Import.ps1`

**This is equivalent to:**

`.\LR_True_ID_Import.ps1 -EntityId 0 -Action Synchronise -SyncName 'A/D => CSV => Identities Import' -CsvFileToImportFrom AD-export.csv`

- To get **only the new users** (well, their Identities, if they exist) from the CSV file `AD-export.csv` added to the default `EntityID` *`0`* (**without removing** any old entry that is not in the CSV file currently)

`.\LR_True_ID_Import.ps1 -Action AddNewOnesOnly`

## Note

:exclamation: `EntityID` ***`0`*** (**Global Entity**) is not available if you are a LogRhythm Cloud customer. 

If you try to use `-EntityId 0` and are an LogRhythm Cloud customer, you will get a `404 Error` for each user.

## Parameters:

- **`-CreateConfiguration`**
	- Mandatory: *No*
	- Default: *False*
	- What does it do?
		- Prompt the user and create the configuration file (which you can then find under `config/config.json`)
		- You can re-run this command any time, but it will only prompt for the parts that are missing in the `config.json` file
		- Feel free to edit the `config/config.json` file directly after

- **`-Action`**
	- Mandatory: *No*
	- Default: *Synchronise*
	- Accepted values:
		- `AddNewOnesOnly`
		- `Synchronise`
	- What does it do?
		- Decide to either:
	 		- `AddNewOnesOnly`
		 		- only add Identities that are not yet in the Cloud or Appliance
			- `Synchronise`
				- remove old entries from the Cloud or Appliance that are not in the CSV
				- add new Identities that are not yet in the Cloud or Appliance

- **`-CsvFileToImportFrom`**
	- Mandatory: *No*
	- Default: *'AD-export.csv'*
	- What does it do?
		- Specify which file to pull the Users' details from

- **`-SyncName`**
	- Mandatory: *No*
	- Default: *'A/D => CSV => Identities Import'*
	- What does it do?
		- Specifies the name of the synchronisation job
