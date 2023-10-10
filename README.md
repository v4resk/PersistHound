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
    <img src="https://shields.io/badge/Persistence_Techniques-5-blue?&style=for-the-badge">
  </a>
</p>


# PersistHound
**PersistHound** is a Python script designed to help Blue Teams, Incident Responders, and System Administrators detect and eliminate persistence mechanisms in Windows systems. This tool provides an arsenal of detection techniques to proactively track down and neutralize potential threats, enhancing the security of your Windows environment.

# How to run it ?
First install dependencies
```powershell
python -m pip install -r requirements.txt
```

Run it !
```powershell
#Basic usage
python PersistHound.py
```


# Persistence Techniques Detected

- Run Key ❌
- RunOnce Key ❌
- Image File Execution Options ❌
- Natural Language Development Platform 6 DLL Override Path ❌
- AEDebug Keys ❌
- Windows Error Reporting Debugger ❌
- Windows Error Reporting ReflectDebugger ❌
- Command Prompt AutoRun ❌
- Explorer Load ❌
- Winlogon Userinit ❌
- Winlogon Shell ❌
- Windows Terminal startOnUserLogin ❌
- AppCertDlls DLL Injection ❌
- App Paths Hijacking ❌
- ServiceDll Hijacking ❌
- Group Policy Extensions DLLs ❌
- Winlogon MPNotify ❌
- CHM Helper DLL ❌
- Hijacking of hhctrl.ocx ❌
- Startup Folder ❌
- User Init Mpr Logon Script ❌
- AutodialDLL Winsock Injection ❌
- LSA Extensions DLL ❌
- ServerLevelPluginDll DNS Server DLL Hijacking ❌
- LSA Authentication Packages DLL ❌
- LSA Security Packages DLL ❌
- Winlogon Notify Packages DLL ❌
- Explorer Tools Hijacking ❌
- .NET DbgManagedDebugger ❌
- ErrorHandler.cmd Hijacking ❌
- WMI Subscriptions ❌
- Windows Services ❌
- Terminal Services InitialProgram ❌
- Accessibility Tools Backdoor ❌
- AMSI Providers ❌
- Powershell Profiles ❌
- Silent Exit Monitor ❌
- Telemetry Controller ❌
- RDP WDS Startup Programs ❌
- Scheduled Tasks ❌
- BITS Jobs NotifyCmdLine ❌
- Power Automate ❌
- Screensaver ❌
- Office Templates ❌
- Office AI.exe Hijacking ❌
- Explorer Context Menu Hijacking ❌
- Service Control Manager Security Descriptor Manipulation ❌
- RunEx Key ❌
- RunOnceEx Key ❌
- RID Hijacking ❌
- Suborner Technique ❌

# Credits
This project is juste a python adaptation of the [PersistenceSniper](https://github.com/last-byte/PersistenceSniper) project. I extend my gratitude to the creators and contributors of PersistenceSniper for their pioneering work, which served as a significant inspiration.