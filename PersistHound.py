import subprocess
import re
import os

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

def find_certificate_info(executable):
        #TO DO
        return "Unknown error occurred"

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

def get_if_builtin_binary(executable):
        #TO DO
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

if __name__ == "__main__":
    executable = 'cmd.exe /c echo Hello, World!'
    cmdlineIs = get_executable_from_command_line(executable)
    print(cmdlineIs)
    executable = 'cmd.exe'
    is_lolbin = get_if_lolbin(executable)
    print(is_lolbin)
    exit(0)
# end main