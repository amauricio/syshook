
@echo off
set CC=CL.exe
set CLINK=link.exe

set WORKDIR=.
set ENTRY_FILE=%WORKDIR%/syshook.c
set DEPS=*.c
set RELEASE_NAME=syshook
set SUBSYSTEM=console
set COMMON_LIB=
set MACHINE=X64
set PROGRAM_FILES=%programfiles(x86)%
set RELEASE_FOLDER=%WORKDIR%\Release
Rem clean all
echo [-] Clean data
DEL /F/Q/S "%RELEASE_FOLDER%" > remote.log


Rem ;;highestAvailable <- si solicita admin
set LEVEL=asInvoker

mkdir %RELEASE_FOLDER% 2> NUL
echo [*] Folder Release created.

echo [*] Set Variables
set VISUAL_STUDIO=%PROGRAM_FILES%\Microsoft Visual Studio

if exist "%VISUAL_STUDIO%" (
    echo [*] Found Visual Studio!! 
    echo [*] VSPath : "%VISUAL_STUDIO%"
) else (
    echo [*] Not Found Visual Studio!! 
    set /p VISUAL_STUDIO="[>] Enter Microsoft Visual Studio Path: "
)
echo [!] Building... > remote.log

set ENV=RELEASE

@call "%VISUAL_STUDIO%\2019\Community\VC\Auxiliary\Build\vcvarsall.bat" %MACHINE%

echo [*] Compiling

%CC% /c /I zip/src/  /D %ENV%  /Fa"%RELEASE_FOLDER%\%RELEASE_NAME%.asm" ^
	/D _CONSOLE /DDEBUG=1 /DAPPNAME=\"wps\" /DRELEASE_NAME=\"%RELEASE_NAME%\" /GL- /D _MBCS /D _MBCS /Gm- /EHsc /MT /nologo /Ox /W0 /GS- /Gy /fp:precise /permissive- ^
    /Zc:wchar_t /Zc:forScope /Zc:inline /Fo"%RELEASE_FOLDER%\\" /Fd"%RELEASE_FOLDER%\%RELEASE_NAME%.pdb" /Gd /TC /analyze- ^
    /FC /errorReport:prompt /D _CRT_SECURE_NO_DEPRECATE   %ENTRY_FILE%  /D _WINSOCK_DEPRECATED_NO_WARNINGS

if exist "%RELEASE_FOLDER%\%RELEASE_NAME%.obj" (
    echo [*] Compilation success!!
) else (
    echo [*] Compilation Failed!!
    Exit /B 5
)

set host64="C:\Program Files (x86)\Microsoft Visual Studio\2019\Community\VC\Tools\MSVC\14.28.29910\bin\Hostx64\x64"
%host64%\ml64.exe /c /Cx patching.asm
move patching.obj Release\patching.obj

echo [-] Linking

%CLINK%  /FIXED /ERRORREPORT:PROMPT /OUT:"%RELEASE_FOLDER%\%RELEASE_NAME%.exe"  /subsystem:%SUBSYSTEM% /INCREMENTAL:NO /NOLOGO ^
    kernel32.lib user32.lib gdi32.lib %COMMON_LIB% winspool.lib comdlg32.lib advapi32.lib shell32.lib ^
    ole32.lib oleaut32.lib uuid.lib odbc32.lib odbccp32.lib /MANIFEST /MANIFESTUAC:"level='%LEVEL%' uiAccess='false'" ^
    /manifest:embed /DEBUG:NONE   /PDB:"%RELEASE_FOLDER%\%RELEASE_NAME%.pdb"  ^
    /DYNAMICBASE:NO /NXCOMPAT:NO /IMPLIB:"%RELEASE_FOLDER%\%RELEASE_NAME%.lib" /MACHINE:%MACHINE% ^
     %RELEASE_FOLDER%\*.obj 
 
echo [-] Checking...
if exist "%RELEASE_FOLDER%\%RELEASE_NAME%.exe" (
    echo [*] Success!!
    echo [*] Success!!  >> remote.log
) else (
    echo [!] Failed!!
    echo [!] Failed!! > remote.log
)

