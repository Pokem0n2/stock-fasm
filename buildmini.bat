@echo off
rem build stock_mini.exe (2222 bytes): fasm COFF obj + crinkler
rem adjust VCBIN/SDK to your local VS BuildTools + Windows SDK paths
set VCBIN=C:\Program Files (x86)\Microsoft Visual Studio\18\BuildTools\VC\Tools\MSVC\14.44.35207
set SDK=C:\Program Files (x86)\Windows Kits\10
set LIB=%VCBIN%\lib\x86;%SDK%\lib\10.0.26100.0\um\x86
tools\fasm.exe stock_coff.asm stock_coff.obj
tools\Crinkler.exe /NODEFAULTLIB /UNSAFEIMPORT /ENTRY:start /SUBSYSTEM:WINDOWS /COMPMODE:FAST /HASHSIZE:10 /ORDERTRIES:10 /OUT:stock_mini.exe stock_coff.obj kernel32.lib
dir stock_mini.exe
