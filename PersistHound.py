import subprocess
import re
import os
import ctypes
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
        'Signature': find_certificate_info(executable) if signature is None else signature,
        'IsBuiltinBinary': get_if_builtin_binary(executable) if is_builtin_binary is None else is_builtin_binary,
        'IsLolbin': get_if_lolbin(executable) if is_lolbin is None else is_lolbin,
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
        "VISUALUIAVERIFYNATIVE.EXE", "VSJITDEBUGGER.EXE", "WFC.EXE", "WINWORD.EXE", "WSL.EXE"
    ]
    
    exe = os.path.basename(executable).upper()
    
    if exe in lolbins:
        return True
    
    return False

def find_certificate_info(executable):
    try:
        powershell_command = f'powershell -Command "(Get-AuthenticodeSignature \\"{executable}\\").SignerCertificate.Subject"'
        subject = subprocess.check_output(powershell_command, shell=True, text=True).strip()

        powershell_command = f'powershell -Command "(Get-AuthenticodeSignature \\"{executable}\\").Status"'
        status = subprocess.check_output(powershell_command, shell=True, text=True).strip()

        formatted_string = f"Status = {status}, Subject = {subject}"
        return formatted_string

    except subprocess.CalledProcessError as e:
        return "Unknown error occurred"

def get_if_builtin_binary(executable):
    try:
        powershell_command = f'powershell -Command "(Get-AuthenticodeSignature \\"{executable}\\").IsOSBinary"'
        result = subprocess.check_output(powershell_command, shell=True, text=True).strip()

        # If the PowerShell command returns 'True', it's a built-in binary; otherwise, it's not.
        return result.lower() == 'true'

    except Exception as e:
        return False
    
def get_if_safe_executable(executable):
    exe_path = get_executable_from_command_line(executable)
    if get_if_builtin_binary(exe_path) and not get_if_lolbin(exe_path):
        return True
    else:
        return False

def get_if_safe_library(dll_full_path):
    if get_if_builtin_binary(dll_full_path):
        return True
    else:
        return False

def parse_net_user():
        return 0



def get_registry_key_values(hive, subkey):
    try:
        # Open the registry key for reading
        print(type(hive))
        print(type(subkey))
        key = winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ)

        values = {}
        index = 0

        # Iterate through the values in the registry key
        while True:
            try:
                name, data, value_type = winreg.EnumValue(key, index)
                values[name] = (data, value_type)
                index += 1
            except FileNotFoundError:
                break

        winreg.CloseKey(key)
        return values
    except FileNotFoundError:
        return {}
    
def get_run_and_runOnce():
    for hive in system_and_users_hives:
        # Define the registry subkey paths for Run and RunOnce
        run_subkey = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
        run_once_subkey = r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce"

        # Retrieve the values in the Run subkey using the provided function
        run_values = get_registry_key_values(hive, run_subkey)
        run_once_values = get_registry_key_values(hive, run_once_subkey)

        # Define the access based on the current hive
        if hive in ['HKEY_LOCAL_MACHINE', 'HKEY_USERS\S-1-5-18', 'HKEY_USERS\S-1-5-19', 'HKEY_USERS\S-1-5-20']:
            access = 'System'
        else:
            access = 'User'

        # Process Run values
        for name, (data, value_type) in run_values.items():

            if not get_if_safe_executable(data):
                # Call new_persistence_object to create a persistence object
                persistence_object = new_persistence_object(
                    hostname=hostname,
                    technique='Registry Run Key' if "Run" in run_subkey else 'Registry RunOnce Key',
                    classification='MITRE ATT&CK T1547.001',
                    path=run_subkey + '\\' + name,
                    value=data,
                    access_gained=access,
                    note='Executables in properties of the key (HKLM|HKEY_USERS<SID>)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run are run when the user logs in or when the machine boots up (in the case of the HKLM hive).',
                    reference='https://attack.mitre.org/techniques/T1547/001/'
                )
                persistence_object_array.append(persistence_object)
                persistence_object_to_string(persistence_object)

        # Process RunOnce values
        for name, (data, value_type) in run_once_values.items():

            if not get_if_safe_executable(data):
                # Call new_persistence_object to create a persistence object
                persistence_object = new_persistence_object(
                    hostname=hostname,
                    technique='Registry Run Key' if "Run" in run_once_subkey else 'Registry RunOnce Key',
                    classification='MITRE ATT&CK T1547.001',
                    path=run_once_subkey + '\\' + name,
                    value=data,
                    access_gained=access,
                    note='Executables in properties of the key (HKLM|HKEY_USERS<SID>)\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run are run when the user logs in or when the machine boots up (in the case of the HKLM hive).',
                    reference='https://attack.mitre.org/techniques/T1547/001/'
                )
                persistence_object_array.append(persistence_object)
                persistence_object_to_string(persistence_object)

        print('')  # Add a newline between Run and RunOnce

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


def get_all_hives():
    try:
        hku_key = winreg.HKEY_USERS
        index = 0
        while True:
            try:
                sid_key_name = winreg.EnumKey(hku_key, index)
                sid_key = winreg.OpenKey(hku_key, sid_key_name)
                system_and_users_hives.append(sid_key)
                index += 1
            except FileNotFoundError:
                break
    except Exception as e:
        print(f"An error occurred: {e}")

#Global vars
persistence_object_array = []
hostname = os.environ.get('COMPUTERNAME')

#REG
hklm_key = winreg.HKEY_LOCAL_MACHINE
hku_key = winreg.HKEY_USERS


system_and_users_hives = [hklm_key]


#Update system_and_users_hives
get_all_hives()




if __name__ == "__main__":
    executable = 'cmd.exe /c echo Hello, World!'
    print(f"Full CMD: {executable}")

    cmdline = get_executable_from_command_line(executable)
    print(f"CMDLINE: {cmdline}")

    executable2 = 'cmd.exe'
    is_lolbin = get_if_lolbin(executable2)
    print(f"is_lolbin? {is_lolbin}")

    certificate_info = find_certificate_info(cmdline)
    print(f"certificate_info: {certificate_info}")

    is_builtin_binary = get_if_builtin_binary(cmdline)
    print(f"is_builtin_binary: {is_builtin_binary}")

    is_safe_executable = get_if_safe_executable(executable)
    print(f"is_safe_executable: {is_safe_executable}")

    library = 'C:\Windows\System32\crypt32.dll'
    is_safe_library = get_if_safe_library(library)
    print(f"is_safe_library: {is_safe_library}")

    print(f"Hostname: {hostname}")

    print("hives: ")
    for hive in system_and_users_hives:
        print(hive)

    get_run_and_runOnce()



# end main