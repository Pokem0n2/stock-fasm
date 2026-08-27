@echo off
rem x86 build: vcvarsall x86 is broken on this machine, set env manually
set VCBIN=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.44.35207
set SDK=C:\Program Files (x86)\Windows Kits\10
set PATH=%VCBIN%\bin\HostX64\x86;%PATH%
set INCLUDE=%VCBIN%\include;%SDK%\Include\10.0.26100.0\um;%SDK%\Include\10.0.26100.0\shared;%SDK%\Include\10.0.26100.0\winrt;%SDK%\Include\10.0.26100.0\ucrt
set LIB=%VCBIN%\lib\x86;%SDK%\lib\10.0.26100.0\um\x86
cl /nologo /O1 /GS- /c stock.c
link /nologo /NODEFAULTLIB /ENTRY:WinMainCRTStartup /SUBSYSTEM:WINDOWS /OPT:REF /OPT:ICF /ALIGN:512 /FILEALIGN:512 /STUB:stub.bin /FIXED /DYNAMICBASE:NO /GUARD:NO /NOCOFFGRPINFO /SAFESEH:NO /MERGE:.rdata=.text /MERGE:.data=.text /SECTION:.text,ERW stock.obj /OUT:stock32.exe kernel32.lib user32.lib gdi32.lib wininet.lib
dir stock32.exe
