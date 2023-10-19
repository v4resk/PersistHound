import subprocess
import re
import os
import win32com.client
import winreg



def new_persistence_object(
    hostname=None, technique=None, classification=None, path=None,
    value=None, access_gained=None, note=None, reference=None, signature=None,
    is_builtin_binary=False, is_lolbin=False
):
    executable = get_executable_from_command_line(value)

    persistence_object = {
        'Hostname': hostname,
        'Technique': technique,
        'Classification': classification,
        'Path': path,
        'Value': value,
        'Access Gained': access_gained,
        'Note': note,
        'Reference': reference,
        'Signature': find_certificate_info(executable),
        'IsBuiltinBinary': get_if_builtin_binary(executable),
        'IsLolbin': get_if_lolbin(executable),
    }

    return persistence_object

def get_executable_from_command_line(path_name):
    path_name = os.path.expandvars(path_name).replace('"', '')

    match = re.search(r'[A-Za-z0-9\s]+\.(exe|dll|ocx|cmd|bat|ps1)', path_name, re.IGNORECASE)
    if match:
        # Grab Index from the re.search() result
        index = match.start()

        # Substring using the index we obtained above
        things_before_match = path_name[:index]
        executable = things_before_match + match.group()
    else:
        executable = None

    if not os.path.isabs(executable):
        try:
            # Use subprocess to find the executable in the system's PATH
            command_output = subprocess.check_output(['where', executable])
            executable = command_output.decode().strip()
        except subprocess.CalledProcessError:
            executable = None

    return executable

def get_if_lolbin(executable):
    if executable == None:
        return None
    # To get an updated list of lolbins 
    # curl https://lolbas-project.github.io/# | grep -E "bin-name\">(.*)\.exe<" -o | cut -d ">" -f 2 | cut -d "<" -f 1 
    lolbins = [
        "APPINSTALLER.EXE", "ASPNET_COMPILER.EXE", "AT.EXE", "ATBROKER.EXE", "BASH.EXE",
        "BITSADMIN.EXE", "CERTOC.EXE", "CERTREQ.EXE", "CERTUTIL.EXE", "CMD.EXE", "CMDKEY.EXE",
        "CMDL32.EXE", "CMSTP.EXE", "CONFIGSECURITYPOLICY.EXE", "CONHOST.EXE", "CONTROL.EXE",
        "CSC.EXE", "CSCRIPT.EXE", "DATASVCUTIL.EXE", "DESKTOPIMGDOWNLDR.EXE", "DFSVC.EXE",
        "DIANTZ.EXE", "DISKSHADOW.EXE", "DNSCMD.EXE", "ESENTUTL.EXE", "EVENTVWR.EXE",
        "EXPAND.EXE", "EXPLORER.EXE", "EXTEXPORT.EXE", "EXTRAC32.EXE", "FINDSTR.EXE",
        "FINGER.EXE", "FLTMC.EXE", "FORFILES.EXE", "FTP.EXE", "GFXDOWNLOADWRAPPER.EXE",
        "GPSCRIPT.EXE", "HH.EXE", "IMEWDBLD.EXE", "IE4UINIT.EXE", "IEEXEC.EXE", "ILASM.EXE",
        "INFDEFAULTINSTALL.EXE", "INSTALLUTIL.EXE", "JSC.EXE", "MAKECAB.EXE", "MAVINJECT.EXE",
        "MICROSOFT.WORKFLOW.COMPILER.EXE", "MMC.EXE", "MPCMDRUN.EXE", "MSBUILD.EXE",
        "MSCONFIG.EXE", "MSDT.EXE", "MSHTA.EXE", "MSIEXEC.EXE", "NETSH.EXE", "ODBCCONF.EXE",
        "OFFLINESCANNERSHELL.EXE", "ONEDRIVESTANDALONEUPDATER.EXE", "PCALUA.EXE", "PCWRUN.EXE",
        "PKTMON.EXE", "PNPUTIL.EXE", "PRESENTATIONHOST.EXE", "PRINT.EXE", "PRINTBRM.EXE",
        "PSR.EXE", "RASAUTOU.EXE", "RDRLEAKDIAG.EXE", "REG.EXE", "REGASM.EXE", "REGEDIT.EXE",
        "REGINI.EXE", "REGISTER-CIMPROVIDER.EXE", "REGSVCS.EXE", "REGSVR32.EXE", "REPLACE.EXE",
        "RPCPING.EXE", "RUNDLL32.EXE", "RUNONCE.EXE", "RUNSCRIPTHELPER.EXE", "SC.EXE",
        "SCHTASKS.EXE", "SCRIPTRUNNER.EXE", "SETTINGSYNCHOST.EXE", "STORDIAG.EXE",
        "SYNCAPPVPUBLISHINGSERVER.EXE", "TTDINJECT.EXE", "TTTRACER.EXE", "VBC.EXE",
        "VERCLSID.EXE", "WAB.EXE", "WLRMDR.EXE", "WMIC.EXE", "WORKFOLDERS.EXE", "WSCRIPT.EXE",
        "WSRESET.EXE", "WUAUCLT.EXE", "XWIZARD.EXE", "ACCCHECKCONSOLE.EXE", "ADPLUS.EXE",
        "AGENTEXECUTOR.EXE", "APPVLP.EXE", "BGINFO.EXE", "CDB.EXE", "COREGEN.EXE", "CSI.EXE",
        "DEVTOOLSLAUNCHER.EXE", "DNX.EXE", "DOTNET.EXE", "DUMP64.EXE", "DXCAP.EXE", "EXCEL.EXE",
        "FSI.EXE", "FSIANYCPU.EXE", "MFTRACE.EXE", "MSDEPLOY.EXE", "MSXSL.EXE", "NTDSUTIL.EXE",
        "POWERPNT.EXE", "PROCDUMP(64).EXE", "RCSI.EXE", "REMOTE.EXE", "SQLDUMPER.EXE", "SQLPS.EXE",
        "SQLTOOLSPS.EXE", "SQUIRREL.EXE", "TE.EXE", "TRACKER.EXE", "UPDATE.EXE", "VSIISEXELAUNCHER.EXE",
        "VISUALUIAVERIFYNATIVE.EXE", "VSJITDEBUGGER.EXE", "WFC.EXE", "WINWORD.EXE", "WSL.EXE", "POWERSHELL.EXE"
    ]
    
    exe = os.path.basename(executable).upper()
    
    if exe in lolbins:
        return True
    
    return False

def find_certificate_info(executable):
    if executable == None:
        return None
    try:
        powershell_command = f'powershell.exe -Command \'(Get-AuthenticodeSignature "{executable}").SignerCertificate.Subject\''
        subject = subprocess.check_output(powershell_command, shell=True, text=True, stderr=None ).strip()

        powershell_command = f'powershell.exe -Command \'(Get-AuthenticodeSignature "{executable}").Status\''
        status = subprocess.check_output(powershell_command, shell=True, text=True ,stderr=None).strip()

        formatted_string = f"Status = {status}, Subject = {subject}"
        return formatted_string

    except subprocess.CalledProcessError as e:
        return "Unknown error occurred"

def get_if_builtin_binary(executable):
    if executable == None:
        return None
    try:
        powershell_command = f'powershell.exe -Command "(Get-AuthenticodeSignature \\"{executable}\\").IsOSBinary"'
        result = subprocess.check_output(powershell_command, shell=True, text=True).strip()

        # If the PowerShell command returns 'True', it's a built-in binary; otherwise, it's not.
        return result.lower() == 'true'

    except Exception as e:
        return False
    
def get_if_safe_executable(executable):
    exe_path = get_executable_from_command_line(executable)
    return get_if_builtin_binary(exe_path) and not get_if_lolbin(exe_path)
    

def get_if_safe_library(dll_full_path):
    if get_if_builtin_binary(dll_full_path):
        return True
    else:
        return False

def parse_net_user():
        return 0

def search_after_comma(data):
    # Split the input string by a comma
    parts = data.split(',')
    
    # Check if there is at least one comma in the string
    if len(parts) > 1:
        # Join all parts except the first one (which is before the first comma)
        result = ','.join(parts[1:])
        return result.strip()  # Remove leading and trailing whitespace
    else:
        # If there are no commas, return an empty string
        return None


def get_registry_key_values(hive,sid,key_name):
    count = 0
    values = {}
    try:
        if sid:
            key = winreg.OpenKey(hive, sid+key_name)
        else:
            key = winreg.OpenKey(hive,key_name)      
        #key = winreg.OpenKey(winreg.HKEY_USERS, sid + key_name)
        i = 0
        while True:

            val = winreg.EnumValue(key, i)
            values[val[0]] = val[1]
            i += 1
            count +=1
        
    except Exception as e:
        # Handle other exceptions
        pass
    return values


def get_registry_persistence(hive,subkey,technique,classification,note,reference):
    # Define the registry subkey paths for Run and RunOnce
    
    sys_sids = ['S-1-5-18', 'S-1-5-19', 'S-1-5-20']
    try:
        if hive == winreg.HKEY_LOCAL_MACHINE:
            access = "System"
            subkey_value = get_registry_key_values(hive, None,subkey)
            if subkey_value:
                for name, data in subkey_value.items():
                    propPath = f"HKLM\\{subkey}\\{name}"
                    if not get_if_safe_executable(data):
                    #if True:
                        # Create a new persistence_object
                        PersistenceObject = new_persistence_object(
                            hostname=hostname,
                            technique=technique,
                            classification=classification,
                            path=propPath,
                            value=data,
                            access_gained=access,
                            note=note,
                            reference=reference
                        )
                        persistence_object_array.append(PersistenceObject)
                        
        elif hive == winreg.HKEY_USERS: 
            for sid in users_sids:
                if sid in sys_sids:
                    access = "System"
                else:
                    access = "User"
                subkey_value = get_registry_key_values(hive, sid,subkey)
                if subkey_value:
                    for name, data in subkey_value.items():
                        propPath = f"HKU\\{sid}{subkey}\\{name}"
                        if not get_if_safe_executable(data):
                        #if True:    
                            # Create a new persistence_object
                                PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=propPath,
                                    value=data,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                                )
                                persistence_object_array.append(PersistenceObject)
    except Exception:
        pass                       


def get_persistence_for_runonceex():

    sys_sids = ['S-1-5-18', 'S-1-5-19', 'S-1-5-20']

    note='Executables in properties of the (HKLM|HKEY_USERS<SID>) Run keys are used when the user logs in or when the machine boots up (in the case of the HKLM hive).'
    reference='https://attack.mitre.org/techniques/T1547/001/'
    technique='Registry Run Keys'
    classification='MITRE ATT&CK T1547.001'

    runonceex_subkey_sys = r'Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
    runonceex_subkey_u = r'\Software\Microsoft\Windows\CurrentVersion\RunOnceEx'
    hklm_key = winreg.HKEY_LOCAL_MACHINE
    hku_key = winreg.HKEY_USERS

    #HKLM
    try:
        key_index = 0
        while True:
            RunOnceEx_key = winreg.OpenKey(hklm_key, runonceex_subkey_sys)
            key_name = winreg.EnumKey(RunOnceEx_key, key_index)
            final_key =  f"{runonceex_subkey_sys}\\{key_name}"
            get_registry_persistence(hklm_key,final_key,technique,classification,note,reference)
            try:
                final_key_depend = f"{final_key}\\Depend"
                runonceex_values_depend = get_registry_key_values(hklm_key, None, final_key_depend)
                if runonceex_values_depend:
                        for name, data in runonceex_values_depend.items():
                            propPath = f"HKLM\\{runonceex_subkey_sys}\\{key_name}\\Depend\\{name}"
                            if not get_if_safe_library(data):
                                # Create a new persistence_object
                                PersistenceObject = new_persistence_object(
                                hostname=hostname,
                                technique=technique,
                                classification=classification,
                                path=propPath,
                                value=data,
                                access_gained=access,
                                note=note,
                                reference=reference
                                )
                                persistence_object_array.append(PersistenceObject)
            except Exception:
                pass    
            key_index += 1
    except Exception:
        pass
    
    #HKU may be useless
    #Check for RunOnceEx on HKU
    for sid in users_sids:
        if sid in sys_sids:
            access = "System"
        else:
            access = "User"

        try:
            key_index = 0
            while True:    

                RunOnceEx_key = winreg.OpenKey(hku_key, sid+runonceex_subkey_u)
                key_name = winreg.EnumKey(RunOnceEx_key, key_index)
                final_key = f"{runonceex_subkey_u}\\{key_name}"
                runonceex_values = get_registry_key_values(hku_key, sid, final_key)
                if runonceex_values:
                    for name, data in runonceex_values.items():
                        propPath = f"HKU\\{sid}{runonceex_subkey_u}\\{key_name}\\{name}"
                        if not get_if_safe_executable(data):
                        #if True:
                            # Create a new persistence_object
                            PersistenceObject = new_persistence_object(
                                hostname=hostname,
                                technique=technique,
                                classification=classification,
                                path=propPath,
                                value=data,
                                access_gained=access,
                                note=note,
                                reference=reference
                            )
                            persistence_object_array.append(PersistenceObject)
                try:
                    final_key_depend = f"{final_key}\\Depend"
                    runonceex_values_depend = get_registry_key_values(hku_key, sid, final_key_depend)
                    if runonceex_values_depend:
                        for name, data in runonceex_values_depend.items():
                            propPath = f"HKU\\{sid}{runonceex_subkey_u}\\{key_name}\\Depend\\{name}"
                            if not get_if_safe_library(data):
                            #if True:
                                # Create a new persistence_object
                                PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=propPath,
                                    value=data,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                                )
                                persistence_object_array.append(PersistenceObject)
                except Exception:
                    pass
                key_index += 1
        except Exception:
                pass
        

    
    
def get_run_keys_persistence():
    note='Executables in properties of the (HKLM|HKEY_USERS<SID>) Run keys are used when the user logs in or when the machine boots up (in the case of the HKLM hive).'
    reference='https://attack.mitre.org/techniques/T1547/001/'
    technique='Registry Run Keys'
    classification='MITRE ATT&CK T1547.001'

    #Subkeys
    ## Run & RunOnce
    run_subkey_sys = r'Software\Microsoft\Windows\CurrentVersion\Run'
    run_once_subkey_sys = r'Software\Microsoft\Windows\CurrentVersion\RunOnce'
    run_subkey_u = r'\Software\Microsoft\Windows\CurrentVersion\Run'
    run_once_subkey_u = r'\Software\Microsoft\Windows\CurrentVersion\RunOnce'
    ## RunServices & RunServicesOnce
    run_services_subkey_sys = r'Software\Microsoft\Windows\CurrentVersion\RunServices'
    run_services_once_subkey_sys = r'Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
    run_services_subkey_u = r'\Software\Microsoft\Windows\CurrentVersion\RunServices'
    run_services_once_subkey_u = r'\Software\Microsoft\Windows\CurrentVersion\RunServicesOnce'
    ## policy settings
    run_policies_subkey_sys = r'Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    run_policies_subkey_u = r'\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run'
    #Hives
    hklm_key = winreg.HKEY_LOCAL_MACHINE
    hku_key = winreg.HKEY_USERS

    #HKLM Run & RunOnce
    get_registry_persistence(hklm_key,run_subkey_sys,technique,classification,note,reference)
    get_registry_persistence(hklm_key,run_once_subkey_sys,technique,classification,note,reference)

    #HKU Run & RunOnce
    get_registry_persistence(hku_key,run_subkey_u,technique,classification,note,reference)
    get_registry_persistence(hku_key,run_once_subkey_u,technique,classification,note,reference)

    #HKLM RunServices & RunServicesOnce
    get_registry_persistence(hklm_key,run_services_subkey_sys,technique,classification,note,reference)
    get_registry_persistence(hklm_key,run_services_once_subkey_sys,technique,classification,note,reference)

    #HKU RunServices & RunServicesOnce
    get_registry_persistence(hku_key,run_services_subkey_u,technique,classification,note,reference)
    get_registry_persistence(hku_key,run_services_once_subkey_u,technique,classification,note,reference)
    
    #HKU & HKLM Run policy settings
    get_registry_persistence(hklm_key,run_policies_subkey_sys,technique,classification,note,reference)
    get_registry_persistence(hku_key,run_policies_subkey_u,technique,classification,note,reference)



def get_image_options_persistence():
    note='executables in the Debugger property of a subkey of (HKLM|HKEY_USERS<SID>)\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\ are run instead of the program corresponding to the subkey. Gained access depends on whose context the debugged process runs in;'
    reference='https://attack.mitre.org/techniques/T1546/012/'
    technique='Image File Execution Options Injection'
    classification='MITRE ATT&CK T1546.012'

    image_options_globalFlag_subkey_sys = r'Software\Microsoft\Windows NT\CurrentVersion\SilentProcessExit'
    image_options_Debugger_subkey_sys = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options'
    hklm_key = winreg.HKEY_LOCAL_MACHINE

    #HKLM
    try:
        key_index = 0
        while True:
            access = "System"
            GloBalFlag_key = winreg.OpenKey(hklm_key, image_options_globalFlag_subkey_sys)
            key_name = winreg.EnumKey(GloBalFlag_key, key_index)
            final_key =  f"{image_options_globalFlag_subkey_sys}\\{key_name}"
            registry_key = winreg.OpenKey(hklm_key, final_key, 0,winreg.KEY_READ)
            try:
                value, regtype = winreg.QueryValueEx(registry_key, "MonitorProcess")
                if value:
                    if not get_if_safe_executable(value):
                    #if True:
                        propPath = f"HKLM\\{final_key}\\MonitorProcess"
                        # Create a new persistence_object
                        PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=propPath,
                                    value=value,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                        )
                        persistence_object_array.append(PersistenceObject)
            except Exception:
                pass
            key_index += 1
    except Exception:
        pass
    
    try:
        key_index = 0
        while True:
            access = "System"
            DebuggerFlag_key = winreg.OpenKey(hklm_key, image_options_Debugger_subkey_sys)
            key_name = winreg.EnumKey(DebuggerFlag_key, key_index)
            final_key =  f"{image_options_Debugger_subkey_sys}\\{key_name}"
            registry_key = winreg.OpenKey(hklm_key, final_key, 0,winreg.KEY_READ)
            try:
                value, regtype = winreg.QueryValueEx(registry_key, "Debugger")
                if value:
                    if not get_if_safe_executable(value):
                    #if True:
                        propPath = f"HKLM\\{final_key}\\Debugger"
                        # Create a new persistence_object
                        PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=propPath,
                                    value=value,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                        )
                        persistence_object_array.append(PersistenceObject)
            except Exception:
                pass
            key_index += 1
    except Exception:
        pass

def get_winlogon_persistence():
    note = 'Adversaries may abuse features of Winlogon to execute DLLs and/or executables when a user logs in'
    reference = 'https://attack.mitre.org/techniques/T1547/004/'
    technique = 'Winlogon Property'
    classification = 'MITRE ATT&CK T1547.004'

    sys_sids = ['S-1-5-18', 'S-1-5-19', 'S-1-5-20']

    subkeys = [r'Userinit', r'Shell']
    win_logon_key = r'Software\Microsoft\Windows NT\CurrentVersion\Winlogon'

    winlogon_notify_subkey_sys = r"Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Notify"
    hklm_key = winreg.HKEY_LOCAL_MACHINE
    hku_key = winreg.HKEY_USERS

    for subkey in subkeys:
        access = 'System'
        try:
            key = winreg.OpenKey(hklm_key,win_logon_key)
            value,_ = winreg.QueryValueEx(key,subkey)
            winreg.CloseKey(key)

            if search_after_comma(value):
                propPath = f"HKLM\\{win_logon_key}\\{subkey}"
                # Create a new persistence_object
                PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=propPath,
                                    value=value,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                        )
                persistence_object_array.append(PersistenceObject)

        except Exception:
            pass

    for subkey in subkeys:
        for sid in users_sids:
            if sid in sys_sids:
                access = "System"
            else:
                access = "User"
                
            try:
                key = winreg.OpenKey(hku_key,sid+"\\"+win_logon_key)
                value,_ = winreg.QueryValueEx(key,subkey)
                winreg.CloseKey(key)

                if search_after_comma(value):
                    propPath = f"HKU\\{sid}\\{win_logon_key}\\{subkey}"
                    # Create a new persistence_object
                    PersistenceObject = new_persistence_object(
                                        hostname=hostname,
                                        technique=technique,
                                        classification=classification,
                                        path=propPath,
                                        value=value,
                                        access_gained=access,
                                        note=note,
                                        reference=reference
                            )
                    persistence_object_array.append(PersistenceObject)

            except Exception:
                pass

    try:
        key_index = 0
        while True:
            access = "System"
            notify_key = winreg.OpenKey(hklm_key, winlogon_notify_subkey_sys)
            key_name = winreg.EnumKey(notify_key, key_index)
            final_key =  f"{winlogon_notify_subkey_sys}\\{key_name}"
            registry_key = winreg.OpenKey(hklm_key, final_key, 0,winreg.KEY_READ)
            try:
                value, regtype = winreg.QueryValueEx(registry_key, "Dllname")
                if value:
                    if not get_if_safe_library(value):
                    #if True:
                        propPath = f"HKLM\\{final_key}\\Dllname"
                        # Create a new persistence_object
                        PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=propPath,
                                    value=value,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                        )
                        persistence_object_array.append(PersistenceObject)
            except Exception:
                pass
            key_index += 1
    except Exception:
        pass


def get_wmi_events_subscription():
    wmi = win32com.client.GetObject("winmgmts:\\root\\Subscription")
    note = 'WMI Events subscriptions can be used to link script/command executions to specific events. Here we list the active consumer events, but you may want to review also existing Filters (with Get-WMIObject -Namespace root\Subscription -Class __EventFilter) and Bindings (with Get-WMIObject -Namespace root\Subscription -Class __FilterToConsumerBinding)'
    reference = 'https://attack.mitre.org/techniques/T1546/003/'
    technique = 'WMI Event Subscription'
    classification = 'MITRE ATT&CK T1546.003'

    # Get CommandLineEventConsumer objects
    cmd_event_consumers = wmi.ExecQuery("SELECT * FROM CommandLineEventConsumer")
    for cmd_entry in cmd_event_consumers:
        path = cmd_entry.Path_.Path
        access = 'System'
        value = f"CommandLineTemplate: {cmd_entry.CommandLineTemplate} / ExecutablePath: {cmd_entry.ExecutablePath}"
        PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=None,
                                    value=value,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                        )
        persistence_object_array.append(PersistenceObject)

    # Get ActiveScriptEventConsumer objects
    script_event_consumers = wmi.ExecQuery("SELECT * FROM ActiveScriptEventConsumer")
    for script_entry in script_event_consumers:
        path = script_entry.Path_.Path
        access = 'System'
        value = f"ScriptingEngine: {script_entry.ScriptingEngine} / ScriptFileName: {script_entry.ScriptFileName} / ScriptText: {script_entry.ScriptText}"
        PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=path,
                                    value=value,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                        )
        persistence_object_array.append(PersistenceObject)

def get_windows_services():
    services = win32com.client.GetObject("winmgmts:").ExecQuery("SELECT Name,DisplayName,State,PathName FROM Win32_Service")
    note = 'Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.'
    reference = 'https://attack.mitre.org/techniques/T1543/003/'
    technique = 'Windows Service'
    classification = 'MITRE ATT&CK T1543.003'
    access = 'system'

    for service in services:
        executable = get_executable_from_command_line(service.PathName)
        if not get_if_safe_executable(service.PathName):
            PersistenceObject = new_persistence_object(
                                    hostname=hostname,
                                    technique=technique,
                                    classification=classification,
                                    path=executable,
                                    value=service.PathName,
                                    access_gained=access,
                                    note=note,
                                    reference=reference
                        )
            persistence_object_array.append(PersistenceObject)


def persistence_object_to_string(persistence_objects):
        print("Hostname:", persistence_objects['Hostname'])
        print("Technique:", persistence_objects['Technique'])
        print("Classification:", persistence_objects['Classification'])
        print("Path:", persistence_objects['Path'])
        print("Value:", persistence_objects['Value'])
        print("Access Gained:", persistence_objects['Access Gained'])
        print("Note:", persistence_objects['Note'])
        print("Reference:", persistence_objects['Reference'])
        print("Signature:", persistence_objects['Signature'])
        print("IsBuiltinBinary:", persistence_objects['IsBuiltinBinary'])
        print("IsLolbin:", persistence_objects['IsLolbin'])
        print()  # Add a newline between objects


def get_all_sids():
    try:
        key_index = 0
        while True:
            key_name = winreg.EnumKey(winreg.HKEY_USERS, key_index)
            users_sids.append(key_name)
            key_index += 1
    except OSError:
        # Cette exception est censée arriver quand toutes les clés ont été
        # énumérées et permet tout simplement de sortir de la boucle infinie
        pass
    except Exception as e:
        print(f"Exception occured: get_all_hives")
        raise e

#Global vars
persistence_object_array = []
hostname = os.environ.get('COMPUTERNAME')

#REG
hklm_key = winreg.HKEY_LOCAL_MACHINE
hku_key = winreg.HKEY_USERS
system_and_users_hives = [hklm_key]
system_and_users_hives.append(hku_key)


#Update SID List
users_sids = []
get_all_sids()


if __name__ == "__main__":
  
    #print(get_executable_from_command_line("cmd.exe /c test.bat"))
    get_run_keys_persistence()
    get_persistence_for_runonceex()
    get_image_options_persistence()
    get_winlogon_persistence()
    get_wmi_events_subscription()
    get_windows_services()

    print()
    for persi in persistence_object_array:
        persistence_object_to_string(persi)

# end main
