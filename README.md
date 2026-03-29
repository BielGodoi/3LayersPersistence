# 3LayersPersistence

Demonstrating 3 persistence layers from a single EXE, that converts itself into proxy DLLs at runtime.

<br>

### Quick Links

[Maldev Academy Home](https://maldevacademy.com?ref=gh)

[Maldev Database](https://search.maldevacademy.com?ref=gh)
  
[Malware Development Course Syllabus](https://maldevacademy.com/maldev-course/syllabus?ref=gh)

[Offensive Phishing Operations Course Syllabus](https://maldevacademy.com/phishing-course/syllabus?ref=gh)

[Ransomware Internals, Simulation and Detection Course Syllabus](https://maldevacademy.com/ransomware-course/syllabus?ref=gh)

<br>

## Persistence Layer 1

Using a permanent WMI subscription (under `ROOT\subscription`), a `RegistryValueChangeEvent` WQL query watches `SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignatureUpdateLastAttempted`, which is a registry value updated every time Windows Defender performs a signature update.

The EXE copies itself to `%SystemRoot%\System32\wbem\SgrmBroker.exe` and registers an `ActiveScriptEventConsumer` running a VBScript that launches it via `Win32_Process.Create`. 

The dropped EXE's filesystem timestamps are cloned from `sihost.exe`.

> [!NOTE]
> Requires administrator privileges.

<br>

## Persistence Layer 2 

The second persistence layer is a COM hijacked CLSID under `HKCU` named `{c53e07ec-25f3-4093-aa39-fc67ea22e99d}`. The real system DLL is `Windows.StateRepositoryPS.dll` (fetched from the `HKLM` CLSID), gets loaded by `svchost.exe`, `OpenWith.exe`, `ms-teams.exe`, `notepad.exe`, `SnippingTool.exe`, and others.

The EXE patches itself into a proxy DLL (named `MsComHost.dll`) whose export table mirrors `Windows.StateRepositoryPS.dll`. `MsComHost.dll` (our DLL) forwards all function calls to `Common.StateRepositoryRM.dll`, which is a renamed copy of the real system DLL (`Windows.StateRepositoryPS.dll`) dropped together to `%APPDATA%\Microsoft\Common\`.

A set of decoy `Ms*.dll` files copied from System32 are dropped into the same directory to make it look like a legitimate directory. All PE timestamps and filesystem timestamps are cloned from the original system DLL.

> [!NOTE]
> Requires no elevation.

<br>

## Persistence Layer 3

Spotify loads `dsound.dll` from its own application directory before falling back to System32, making it vulnerable to DLL search order hijacking. 

The EXE patches itself into a proxy DLL (named `dsound.dll`) whose export table mirrors the real `dsound.dll`. Our DLL forwards all exports to `dspatial.dll`, which is a renamed copy of the real `dsound.dll` DLL. Both DLLs are dropped inside Spotify's `%APPDATA%\Spotify\` directory. 

PE timestamps and filesystem timestamps are cloned from the real System32 `dsound.dll` DLL.

> [!NOTE]
> Requires no elevation.

<br>

## Installation Check
 
A DWORD registry value (`HKCU\Software\MaldevAcademy\XXXX\AppIdentifier`) is written on first run. On subsequent executions (e.g., when triggered by WMI), the EXE detects this flag and skips re-installation, jumping directly to the payload execution.

<br>

## Mutex Guard

A machine-unique global mutex prevents the payload from executing concurrently across multiple processes. This is important for the DLL layers, since `MsComHost.dll` and `dsound.dll` get loaded into multiple processes simultaneously, without a guard, the payload would fire once per host process.
The mutex name is derived at compile time from the `__TIME__` macro mixed with the volume serial number of the system drive at runtime, producing a name that is unique per machine.

<br>

## EXE-to-DLL Patching

The patching process reads the EXE from disk into memory, then applies the following patches from within the [ConvertExecutableToDll](https://github.com/Maldev-Academy/3LayersPersistence/blob/main/3LayersPersistence/ConvertExeToDll.c#L560) function:

- `IMAGE_FILE_DLL` is set in `FileHeader.Characteristics`
- `AddressOfEntryPoint` is redirected to the RVA of [DllMain](https://github.com/Maldev-Academy/3LayersPersistence/blob/main/3LayersPersistence/Main.c#L122).
- `Subsystem` is set to `IMAGE_SUBSYSTEM_WINDOWS_GUI`
- The target system DLL's exports are read and a forwarded export table is built, with every export pointing to the renamed copy of the real system DLL
- The export table is appended as a new `.edata` section
- Stomps all PE timestamps (NT header, export directory, debug directory) to 30 days before the original DLL's timestamp.

The resulting binary is a functional proxy DLL that mirrors the hijacked system DLL's exports and forwards all calls to the legitimate DLL.

<br>

## Verification & Cleanup

After execution, one can run [VerifyPersistence.ps1](https://github.com/Maldev-Academy/3LayersPersistence/blob/main/VerifyPersistence.ps1) to inspect all dropped files, registry keys, exports, and timestamps. Additionaly, for cleanup, [CleanupScript.ps1](https://github.com/Maldev-Academy/3LayersPersistence/blob/main/CleanupScript.ps1) should be executed.

<br>

## Compilation Modes

| Configuration | Logging | Logging Strings |
|---|---|---|
| `Debug` | DbgView + Console Window (In DLLs Also) | Present |
| `Release` | DbgView only | Present |
| `Stripped` | None | Removed |

In `Stripped` mode, all logging macros compile to nothing and strings are removed, producing a clean binary with no debug artifacts. It also replaces the default entry point with a custom [EntryPoint](https://github.com/Maldev-Academy/3LayersPersistence/blob/main/3LayersPersistence/Main.c#L304) that calls `main` and exits via `ExitProcess`, avoiding CRT linking.















