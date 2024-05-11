import logging
import re
from typing import Optional, Tuple

import colorama
from requests import exceptions as requests_exceptions
from requests import get as requests_get
from semver import Version

from constants import VERSION

import time
import subprocess

from sys import exit

# https://python-semver.readthedocs.io/en/latest/advanced/deal-with-invalid-versions.html
BASEVERSION = re.compile(
    r"""[vV]?
        (?P<major>0|[1-9]\d*)
        (\.
        (?P<minor>0|[1-9]\d*)
        (\.
            (?P<patch>0|[1-9]\d*)
        )?
        )?
    """,
    re.VERBOSE,
)

UPDATE_SCRIPT_NAME = 'auto-updater.py'

def generate_update_script(binary_url, sig_url):
    logging.debug("generate_update_script: called")
    with open(UPDATE_SCRIPT_NAME, 'w') as update_script:
        update_script.write(f'''
import os
import shutil
import subprocess
import sys
import time
import gnupg

from requests import get as requests_get

def download_file(url, filename):
    try:
        r = requests_get(url=url, stream=True)
        with open(filename, 'wb') as f:
            shutil.copyfileobj(r.raw, f)
    except Exception as e:
        print(f"Download and replace failed: {{e}}")
    
def verify_sig(downloaded, signature, public_key):
    gpg = gnupg.GPG()
    with open(public_key, 'r') as key_file:
        public_key_data = key_file.read()
        gpg.import_keys(public_key_data)
    with open(signature, 'rb') as sig_file:
        verified = gpg.verify_file(sig_file, downloaded)
        return verified

def download_and_verify(binary, sig, pub, filename):
    time.sleep(2)
    download_file(binary, "sgplus-temp.exe")
    download_file(sig, "sgplus.exe.sig")
    download_file(pub, "public_key.asc")
    print("Files downloaded successfully. Verifying files...")

    if verify_sig("sgplus-temp.exe", "sgplus.exe.sig", "public_key.asc"):
        print("Files verified successfully. Continuing...")
        os.rename("sgplus-temp.exe", "sgplus.exe")
        print("Opening new version. Enjoy!\\n\\n\\n")
        subprocess.Popen("sgplus.exe", creationflags = subprocess.CREATE_NEW_PROCESS_GROUP)
    else:
        print("Files could not be verified. Aborting update.")
        os.remove("sgplus-temp.exe")

download_binary = "{binary_url}"
download_sig = "{sig_url}"
public_key = "https://github.com/cvbnxx/SCR-SGPlus/blob/verification/public_key.asc"
download_and_verify(download_binary, download_sig, public_key, "sgplus.exe") #Assumes sgplus.exe is the exact file name to be replaced, new version will be downloaded as sgplus.exe regardless but the old version will not be replaced if named something else.

os.remove("sgplus.exe.sig")
os.remove("public_key.asc")
os.remove(__file__)
''')

def execute_update_script():
    logging.debug("execute_update_script: called")
    try:
        subprocess.Popen(["python", UPDATE_SCRIPT_NAME], creationflags = subprocess.CREATE_NEW_PROCESS_GROUP)
        exit()
    except Exception as e:
        logging.error(f"execute_update_script: Execution failed: {e}")
        print("Failed to execute update script")
        
def coerce(version: str) -> Tuple[Version, Optional[str]]:
    """
    Convert an incomplete version string into a semver-compatible Version
    object

    * Tries to detect a "basic" version string (``major.minor.patch``).
    * If not enough components can be found, missing components are
        set to zero to obtain a valid semver version.

    :param str version: the version string to convert
    :return: a tuple with a :class:`Version` instance (or ``None``
        if it's not a version) and the rest of the string which doesn't
        belong to a basic version.
    :rtype: tuple(:class:`Version` | None, str)
    """
    match = BASEVERSION.search(version)
    if not match:
        return (None, version)

    ver = {key: 0 if value is None else value for key, value in match.groupdict().items()}
    ver = Version(**ver)
    rest = match.string[match.end() :]  # noqa:E203
    return ver, rest


def check_for_updates() -> None:
    logging.debug("update_check: called")
    """Fetch the latest release version from the GitHub repo and inform the user if an update is available"""
    URL = "https://api.github.com/repos/cvbnxx/SCR-SGPlus/releases/latest"
    try:
        r = requests_get(url=URL, timeout=10)
        data = r.json()
        tag = coerce(data["tag_name"])
        our_tag = coerce(VERSION)
        if our_tag < tag:
            print(f"{colorama.Fore.RED}NOTICE: A new update is available for SG+!")
            print(
                "It is always recommended to update to the latest version. To do so, go to https://github.com/ElectricityMachine/SCR-SGPlus"
            )
            print('and follow the instructions under "Installation"')
            print(colorama.Fore.WHITE)

            ###
            download_binary_url = data['assets'][0]['browser_download_url'] #Assumes the exe is the first file in Assets
            download_signature_url = data['assets'][1]['browser_download_url']
            generate_update_script(download_binary_url, download_signature_url)
            print("Installing update. Please wait...")
            time.sleep(1)
            execute_update_script()
            ###
            
        else:
            logging.info("No new updates found.")
    except requests_exceptions.RequestException as e:
        logging.error(f"update_check: RequestException occurred: {e}")
        logging.error("Update check failed. Please ensure you have allowed sgplus.exe in your firewall.")
        logging.info("Skipping update check because we errored...")
