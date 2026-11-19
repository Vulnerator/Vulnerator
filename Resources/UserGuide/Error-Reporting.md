# Error Reporting

## The log

Vulnerator writes a log named **V6Log.txt**:

* Portable mode: the **Logs** folder next to Vulnerator.exe (or `%LOCALAPPDATA%\Vulnerator\Logs` when that folder is
  read-only)
* Persistent mode: `%LOCALAPPDATA%\Vulnerator\Logs`
* The exact path is shown in any error message Vulnerator displays

The log records each file processed, the number of rules and findings read, and the details of any error.

## Reporting a problem

1. Note what you did and what you expected.
2. Copy the relevant part of the log. **Remove host names, IP addresses and anything sensitive before sharing it**, and
   do not attach your scans, checklists or exports.
3. Open an issue at https://github.com/hbonesctr/Vulnerator/issues (or use the bug button at the top of the window)
   with the steps and the log extract.

## Common messages

* **"No STIG library has been loaded"** - load the library under Settings > STIG Library, or continue without it.
* **"Database engine unavailable"** - Vulnerator uses winsqlite3.dll from Windows (System32); the message gives the
  detail to pass to your system administrator.
* **"imported as a STIG baseline"** - the checklist has no host name, FQDN or IP address, so only its rules were loaded.
* **Files in "Previous" folders skipped** - expected for Evaluate-STIG output; see Using the Software.
