# DLL-hijack-X64
This is a python script to generate a hijacked dll to do whatever you want 
## Features:
1. Support C++.
2. For X64 DLL only.
3. Generate a VS2017 project, which can be compiled directly.

## Attention:
1. perhaps not all dll can be hijacked, i've tested version.dll and msimg32.dll, they work perfectly
2. sometimes even dlls can be hijacked, the operating system will load them from original system dll path, you can look up KnownDLLs in Regedit for more detail(different version of your windows are different in KnownDLLs).
3. 64 bit dlls are in \Windows\System32, not \Windows\SysWow64 when you are running 64 bit OS.
4. The generated project is using MT Mode, which means the dll will include the VC runtime, thus the size of dll will be larger, but the benefit is that we do not need to worry about VC runtime.If You do not want to use MT Mode, change to MD Mode.
