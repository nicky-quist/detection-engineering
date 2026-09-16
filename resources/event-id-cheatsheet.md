# Windows Event ID Cheatsheet (SOC Basics)

## Sysmon (Microsoft Sysinternals)
- **1** Process Create (Image, CommandLine, ParentImage, User, Hashes)
- **3** Network Connection (Image, DestinationIp, DestinationPort, Protocol)
- **7** Image Loaded (DLL loads; useful but noisy)
- **11** File Create (drops, suspicious writes)
- **13** Registry Value Set (persistence keys)
- **22** DNS Query (domains queried; great for hunting)

## Windows Security Log
- **4624** Logon Success (LogonType matters)
- **4625** Logon Failure (watch for spray/brute force patterns)
- **4672** Special privileges assigned to new logon (admin-ish)
- **4688** Process Creation (if enabled; Sysmon is usually better)
- **4720** User account created
- **4728/4732** User added to privileged group
