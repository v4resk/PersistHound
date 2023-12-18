import subprocess
import re
import os
import win32com.client
import winreg
import time
import psutil



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
    try:
        path_name = os.path.expandvars(path_name).replace('"', '')

        match = re.search(r'[A-Za-z0-9\s]+\.(exe|dll|ocx|cmd|bat|ps1)', path_name, re.IGNORECASE)
        if match:
            index = match.start()
            things_before_match = path_name[:index]
            executable = things_before_match + match.group()
        else:
            executable = None

        if not os.path.isabs(executable):
            try:
                command_output = subprocess.check_output(['where', executable])
                executable = command_output.decode().strip()
            except subprocess.CalledProcessError:
                executable = None

        return executable
    except Exception:
        return path_name


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
    
    return exe in lolbins


def find_certificate_info(executable):
    if not executable:
        return None

    try:
        powershell_command = f'chcp 65001 |powershell.exe -Command "(Get-AuthenticodeSignature \\"{executable}\\" -ErrorAction SilentlyContinue).SignerCertificate.Subject"'
        subject = subprocess.check_output(powershell_command, shell=True, text=True, stderr=None).strip()

        powershell_command = f'chcp 65001 |powershell.exe -Command "(Get-AuthenticodeSignature \\"{executable}\\" -ErrorAction SilentlyContinue).Status"'
        status = subprocess.check_output(powershell_command, shell=True, text=True, stderr=None).strip()

        formatted_string = f"Status = {status}, Subject = {subject}"
        return formatted_string

    except subprocess.CalledProcessError as e:
        return "Error Occured"
        pass

def get_if_builtin_binary(executable):
    if not executable:
        return False

    try:
        # Check if the executable is in a system directory
        is_system_binary = any(
            os.path.dirname(executable).lower() == sys_dir.lower()
            for sys_dir in os.environ['PATH'].split(os.pathsep)
        )

        if is_system_binary:
            return True

        # Additional checks here (e.g., certificate validation)
        result_cert = find_certificate_info(executable)
        result_cert_valide = result_cert.startswith("Status = Valid")
        result_cert_Microsoft = "CN=Microsoft Corporation, O=Microsoft Corporation, L=Redmond, S=Washington, C=US" in result_cert

        return result_cert_valide and result_cert_Microsoft

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
    services = win32com.client.GetObject("winmgmts:").ExecQuery("SELECT Name,DisplayName,State,PathName FROM Win32_Service WHERE PathName IS NOT NULL")
    note = 'Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.'
    reference = 'https://attack.mitre.org/techniques/T1543/003/'
    technique = 'Windows Service'
    classification = 'MITRE ATT&CK T1543.003'
    access = 'system'

    for service in services:
        service_binPath = service.PathName
        if service_binPath and not get_if_safe_executable(service_binPath):
                PersistenceObject = new_persistence_object(
                                        hostname=hostname,
                                        technique=technique,
                                        classification=classification,
                                        path=service.Name,
                                        value=service_binPath,
                                        access_gained=access,
                                        note=note,
                                        reference=reference
                            )
                persistence_object_array.append(PersistenceObject)

def get_windows_services2():
    note = 'Adversaries may create or modify Windows services to repeatedly execute malicious payloads as part of persistence. When Windows boots up, it starts programs or applications called services that perform background system functions.'
    reference = 'https://attack.mitre.org/techniques/T1543/003/'
    technique = 'Windows Service'
    classification = 'MITRE ATT&CK T1543.003'
    access = 'system'

    for service in psutil.win_service_iter():
        service_binPath = service.binpath()
        service_name = service.name()
        if not get_if_safe_executable(service_binPath):
                PersistenceObject = new_persistence_object(
                                        hostname=hostname,
                                        technique=technique,
                                        classification=classification,
                                        path=service_name,
                                        value=service_binPath,
                                        access_gained=access,
                                        note=note,
                                        reference=reference
                            )
                persistence_object_array.append(PersistenceObject)


def get_scheduled_tasks():

    note = 'Adversaries may create or modify scheduled tasks to repeatedly execute malicious payloads as part of persistence. Scheduled tasks allow users to run programs or scripts at predefined times or intervals.'
    reference = 'https://attack.mitre.org/techniques/T1053/'
    technique = 'Scheduled Task'
    classification = 'MITRE ATT&CK T1053'

    scheduler = win32com.client.Dispatch('Schedule.Service')
    scheduler.Connect()
    root_folder = scheduler.GetFolder('\\')
    tasks = root_folder.GetTasks(0)

    for task in tasks:
        if task.Path:
            author, run_as_user = get_task_users(task)
            value = get_task_actions(task)
            access = f"runAs: {run_as_user} / Author: {author}"
            if not get_if_safe_executable(value):
                PersistenceObject = new_persistence_object(
                                        hostname=hostname,
                                        technique=technique,
                                        classification=classification,
                                        path=task.Path,
                                        value=value,
                                        access_gained=access,
                                        note=note,
                                        reference=reference
                )
                persistence_object_array.append(PersistenceObject)


def get_task_actions(task):
    # Get the task definition
    task_def = task.Definition

    # Initialize an empty list to store task actions
    task_actions = []

    # Loop through the task definition's actions
    for action in task_def.Actions:
        if action.Type == 0:  # 0 corresponds to "Execute" action
            task_actions.append(action.Path)

    return " / ".join(task_actions)  # Join multiple actions with newlines

def get_task_users(task):
    task_def = task.Definition
    principal = task_def.Principal
    author = principal.UserId
    run_as_user = principal.RunLevel
    return author, run_as_user


def get_startup_folder():
    note = 'Placing a program within a startup folder will also cause that program to execute when a user logs in.'
    reference = 'https://attack.mitre.org/techniques/T1053/'
    technique = 'Startup Folder'
    classification = 'MITRE ATT&CK T1547.001'
    access= 'User'

    user_directories = os.listdir('C:\\Users\\')
    for directory in user_directories:
        full_path = os.path.join('C:\\Users\\', directory)
        startup_directory = os.path.join(full_path, 'AppData', 'Roaming', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')

        if os.path.exists(startup_directory):
            for file in os.listdir(startup_directory):
                rel_path = file
                if not get_if_safe_executable(rel_path):
                    PersistenceObject = new_persistence_object(
                                        hostname=hostname,
                                        technique=technique,
                                        classification=classification,
                                        path=startup_directory,
                                        value=rel_path,
                                        access_gained=access,
                                        note=note,
                                        reference=reference
                    )
                    persistence_object_array.append(PersistenceObject)

    startup_directory = os.path.join('C:\\', 'ProgramData', 'Microsoft', 'Windows', 'Start Menu', 'Programs', 'Startup')
    access= 'All Users'
    if os.path.exists(startup_directory):
            for file in os.listdir(startup_directory):
                rel_path = file
                if not get_if_safe_executable(rel_path):
                    PersistenceObject = new_persistence_object(
                                        hostname=hostname,
                                        technique=technique,
                                        classification=classification,
                                        path=startup_directory,
                                        value=rel_path,
                                        access_gained=access,
                                        note=note,
                                        reference=reference
                    )
                    persistence_object_array.append(PersistenceObject)


def get_DLLPathOverride():
    note = 'DLLs listed in properties of subkeys of (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe'
    reference = 'https://red.infiltr8.io/windows/persistence/registry/natural-language-6-dlls'
    technique = 'Natural Language Development Platform 6 DLL Override Path'
    classification = 'MITRE ATT&CK TA0003'
    access = "System"

    Natural_Language_subkey_sys = r'System\CurrentControlSet\Control\ContentIndex\Language'
    hklm_key = winreg.HKEY_LOCAL_MACHINE

    try:
        key_index = 0
        while True:
            nl6_keys = winreg.OpenKey(hklm_key, Natural_Language_subkey_sys)
            key_name = winreg.EnumKey(nl6_keys, key_index)
            final_key =  f"{Natural_Language_subkey_sys}\\{key_name}"
            registry_key = winreg.OpenKey(hklm_key, final_key, 0,winreg.KEY_READ)
            try:
                value, regtype = winreg.QueryValueEx(registry_key, "StemmerDLLPathOverride")
                if value:
                    if not get_if_safe_library(value):
                    #if True:
                        propPath = f"HKLM\\{final_key}\\StemmerDLLPathOverride"
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
            nl6_keys = winreg.OpenKey(hklm_key, Natural_Language_subkey_sys)
            key_name = winreg.EnumKey(nl6_keys, key_index)
            final_key =  f"{Natural_Language_subkey_sys}\\{key_name}"
            registry_key = winreg.OpenKey(hklm_key, final_key, 0,winreg.KEY_READ)
            try:
                value, regtype = winreg.QueryValueEx(registry_key, "WBDLLPathOverride")
                if value:
                    if not get_if_safe_library(value):
                    #if True:
                        propPath = f"HKLM\\{final_key}\\WBDLLPathOverride"
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

def get_AEDebug():
    note = 'DLLs listed in properties of subkeys of (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\ContentIndex\Language are loaded via LoadLibrary executed by SearchIndexer.exe'
    reference = 'https://red.infiltr8.io/windows/persistence/registry/aedebug-keys'
    technique = 'AEDebug Custom Debugger'
    classification = 'MITRE ATT&CK TA0003'
    hklm_key = winreg.HKEY_LOCAL_MACHINE
    access = 'System'

    aedebug_key1 = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\AeDebug'
    aedebug_key2 = r'SOFTWARE\Wow6432Node\Microsoft\Windows NT\CurrentVersion\AeDebug'

    try:
        registry_key = winreg.OpenKey(hklm_key, aedebug_key1, 0,winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, "Debugger")
        if value:
                    if not get_if_safe_executable(value):
                    #if True:
                        propPath = f"HKLM\\{aedebug_key1}\\Debugger"
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
        registry_key = winreg.OpenKey(hklm_key, aedebug_key2, 0,winreg.KEY_READ)
        value, regtype = winreg.QueryValueEx(registry_key, "Debugger")
        if value:
                    if not get_if_safe_executable(value):
                    #if True:
                        propPath = f"HKLM\\{aedebug_key2}\\Debugger"
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

    
def get_lsa_ssp_ddl():
    note = 'The DLLs specified in the "Security Packages" property of the (HKLM|HKEY_USERS\<SID>)\SYSTEM\CurrentControlSet\Control\Lsa\ key are loaded by LSASS at machine boot.'
    reference = 'https://attack.mitre.org/techniques/T1547/005/'
    technique = 'LSA Security Package DLL'
    classification = 'MITRE ATT&CK T1547.005'
    hklm_key = winreg.HKEY_LOCAL_MACHINE
    access = 'System'

    sec_pckgs = [r'SYSTEM\CurrentControlSet\Control\Lsa', r'SYSTEM\CurrentControlSet\Control\Lsa\OSConfig']

    for sec_pck in sec_pckgs:
        try:
            registry_key = winreg.OpenKey(hklm_key, sec_pck, 0,winreg.KEY_READ)
            values, regtype = winreg.QueryValueEx(registry_key, "Security Packages")
            
            for dll in values:
                if dll == "":
                    continue
                if not dll.startswith(r"C:\\"):
                    dll_path = f"C:\Windows\System32\{dll}.dll"
                    if not get_if_safe_library(dll_path):
                        #if True:
                            propPath = f"HKLM\\{sec_pck}\\Security Packages"
                            # Create a new persistence_object
                            PersistenceObject = new_persistence_object(
                                        hostname=hostname,
                                        technique=technique,
                                        classification=classification,
                                        path=propPath,
                                        value=dll_path,
                                        access_gained=access,
                                        note=note,
                                        reference=reference
                            )
                            persistence_object_array.append(PersistenceObject)
        except Exception as e:
                    print(e)
                    pass



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

    time_start = time.perf_counter()
    get_run_keys_persistence()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_run_keys_persistence took {time_duration:.3f} seconds')
    
    time_start = time.perf_counter()
    get_persistence_for_runonceex()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_persistence_for_runonceex took {time_duration:.3f} seconds')

    time_start = time.perf_counter()
    get_image_options_persistence()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_image_options_persistence took {time_duration:.3f} seconds')

    time_start = time.perf_counter()
    get_winlogon_persistence()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_winlogon_persistence took {time_duration:.3f} seconds')
    
    time_start = time.perf_counter()
    get_wmi_events_subscription()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_wmi_events_subscription took {time_duration:.3f} seconds')

    time_start = time.perf_counter()
    get_windows_services()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_windows_services took {time_duration:.3f} seconds')

    time_start = time.perf_counter()    
    get_scheduled_tasks()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_scheduled_tasks took {time_duration:.3f} seconds')

    time_start = time.perf_counter()
    get_startup_folder()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_startup_folder took {time_duration:.3f} seconds')

 
    time_start = time.perf_counter()    
    get_DLLPathOverride()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_DLLPathOverride took {time_duration:.3f} seconds')

    time_start = time.perf_counter()
    get_AEDebug()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_AEDebug took {time_duration:.3f} seconds')

    time_start = time.perf_counter()
    get_lsa_ssp_ddl()
    time_end = time.perf_counter()
    time_duration = time_end - time_start
    #print(f'get_lsa_ssp_ddl took {time_duration:.3f} seconds')

    print()
    for persi in persistence_object_array:
        persistence_object_to_string(persi)

# end main
