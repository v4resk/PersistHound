<h1 align="center">
  <br>
  <a href="https://github.com/v4resk/PersistHound/"><img src="https://i.imgur.com/t81dlNk.png" width=260 height=260 alt="PersistHound"></a>
</h1>
<h4 align="center">Persistence Hunting</h4>
<p align="center">
  <a href="https://github.com/v4resk/PersistHound/">
    <img src="https://shields.io/badge/Language-Python-blue?&style=for-the-badge">
  </a>
  <a href="https://github.com/v4resk/PersistHound/">
    <img src="https://shields.io/badge/Persistence_Techniques-15-blue?&style=for-the-badge">
  </a>
</p>


# PersistHound
**PersistHound** is a Python script designed to help Blue Teams, Incident Responders, and System Administrators detect and eliminate persistence mechanisms in Windows systems. This tool provides an arsenal of detection techniques to proactively track down and neutralize potential threats, enhancing the security of your Windows environment.

# How to run it ?

Just run it !
```powershell
#Basic usage
python PersistHound.py
```

# Persistence Techniques Detected

- [Run Key](https://red.infiltr8.io/windows/persistence/registry/run-keys)
- [RunOnce Key](https://red.infiltr8.io/windows/persistence/registry/run-keys)
- [RunOnceEx Key](https://red.infiltr8.io/windows/persistence/registry/run-keys)
- [RunServices Key](https://red.infiltr8.io/windows/persistence/registry/run-keys)
- [RunServicesOnce Key](https://red.infiltr8.io/windows/persistence/registry/run-keys)
- [Windows policy Settings Run Key](https://red.infiltr8.io/windows/persistence/registry/run-keys)
- [Image File Execution Options - Debugger](https://red.infiltr8.io/windows/persistence/registry/image-file-execution-options)
- [Image File Execution Options - GlobalFlag](https://red.infiltr8.io/windows/persistence/registry/image-file-execution-options)
- [Winlogon Userinit](https://red.infiltr8.io/windows/persistence/registry/winlogon)
- [Winlogon Shell](https://red.infiltr8.io/windows/persistence/registry/winlogon)
- [Winlogon Notify Packages DLL](https://red.infiltr8.io/windows/persistence/registry/winlogon)
- [WMI Subscriptions](https://red.infiltr8.io/windows/persistence/wmi-event-subscription)
- [Windows Services](https://attack.mitre.org/techniques/T1543/003/)
- [Scheduled Tasks](https://attack.mitre.org/techniques/T1053/)
- [Startup Folders](https://red.infiltr8.io/windows/persistence/logon-triggered)
- Natural Language Development Platform 6 DLL Override Path ❌
- AEDebug Keys ❌
- Windows Error Reporting Debugger ❌
- Windows Error Reporting ReflectDebugger ❌
- Command Prompt AutoRun ❌
- Explorer Load ❌
- Windows Terminal startOnUserLogin ❌
- AppCertDlls DLL Injection ❌
- App Paths Hijacking ❌
- ServiceDll Hijacking ❌
- Group Policy Extensions DLLs ❌
- Winlogon MPNotify ❌
- CHM Helper DLL ❌
- Hijacking of hhctrl.ocx ❌
- User Init Mpr Logon Script ❌
- AutodialDLL Winsock Injection ❌
- LSA Extensions DLL ❌
- ServerLevelPluginDll DNS Server DLL Hijacking ❌
- LSA Authentication Packages DLL ❌
- LSA Security Packages DLL ❌
- Explorer Tools Hijacking ❌
- .NET DbgManagedDebugger ❌
- ErrorHandler.cmd Hijacking ❌
- Terminal Services InitialProgram ❌
- Accessibility Tools Backdoor ❌
- AMSI Providers ❌
- Powershell Profiles ❌
- Silent Exit Monitor ❌
- Telemetry Controller ❌
- RDP WDS Startup Programs ❌
- BITS Jobs NotifyCmdLine ❌
- Power Automate ❌
- Screensaver ❌
- Office Templates ❌
- Office AI.exe Hijacking ❌
- Explorer Context Menu Hijacking ❌
- Service Control Manager Security Descriptor Manipulation ❌
- RID Hijacking ❌
- Suborner Technique ❌

# Credits
This project is juste a python adaptation of the [PersistenceSniper](https://github.com/last-byte/PersistenceSniper) project. I extend my gratitude to the creators and contributors of PersistenceSniper for their pioneering work, which served as a significant inspiration.
