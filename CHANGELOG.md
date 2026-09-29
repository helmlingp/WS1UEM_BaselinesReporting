# Changelog

All notable changes to this project are documented in this file.

This is the first version-tagged entry for this script; changes prior to
1.2.1 are captured in the git history but not broken out by version number
here.

## [1.2.1] - 2026-09-29

### Changed

- **Device Compliance Status export** (`<log-basename>_Device_Compliance_Status_<BaselineName>.csv`
  and its matching report table) - added `Serial Number`, `OS Version`, and `Last Seen` columns
  (sourced from `Get-Devices`), alongside the previously-added `Organization Group` column.
- **Non-compliant settings export** (renamed from `<log-basename>_Device_NonCompliantControls_<BaselineName>.csv`
  to `<log-basename>_<ComplianceLevel>_<BaselineName>.csv`, e.g. `..._NonCompliant_NotAvailable_...csv`) -
  added `Serial Number`, `OS Version`, and `Last Seen` columns; renamed the `userName` column to
  `User Name` for consistency with the other export; reordered `Compliance Status` ahead of
  `Policy Setting`.
