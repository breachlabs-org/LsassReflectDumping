# LsassReflectDumping
This tool leverages the Process Forking technique using the RtlCreateProcessReflection API to clone the lsass.exe process. Once the clone is created, it utilizes MINIDUMP_CALLBACK_INFORMATION callbacks to generate a memory dump of the cloned process
