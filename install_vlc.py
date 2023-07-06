import re 
import os 
import requests 
import subprocess 
import hashlib 
file_url = 'http://download.videolan.org/pub/videolan/vlc/3.0.17.4/win64/'

def main():

    # Get the expected SHA-256 hash value of the VLC installer
    expected_sha256 = get_expected_sha256()

    # Download (but don't save) the VLC installer from the VLC website
    installer_data = download_installer()

    # Verify the integrity of the downloaded VLC installer by comparing the
    # expected and computed SHA-256 hash values
    if installer_ok(installer_data, expected_sha256):

        # Save the downloaded VLC installer to disk
        installer_path = save_installer(installer_data)

        # Silently run the VLC installer
        run_installer(installer_path)

        # Delete the VLC installer from disk
        delete_installer(installer_path)

def get_expected_sha256():
    """Downloads the text file containing the expected SHA-256 value for the VLC installer file from the 
    videolan.org website and extracts the expected SHA-256 value from it.

    Returns:
        str: Expected SHA-256 hash value of VLC installer
    """
    # TODO: Step 1
    resp_msg = requests.get(file_url)
    if resp_msg.status_code == requests.codes.ok:
        content_file = resp_msg.text 
    else:
        return None
    sha256 = r'SHA-256:[\s]*([A-Fa-f0-9]{64})'
    search_pattern = re.search(sha256, content_file)
    if search_pattern:
        value = search_pattern.group(1)
        return value 
    else:
    # Hint: See example code in lab instructions entitled "Extracting Text from a Response Message Body"
    # Hint: Use str class methods, str slicing, and/or regex to extract the expected SHA-256 value from the text 
        return None 

def download_installer():
    
    # TODO: Step 2
    resp_msg = requests.get(file_url)
    if resp_msg.status_code == requests.codes.ok:
        content_file = resp_msg.content 
    return None 


def installer_ok(installer_data, expected_sha256):
    """Verifies the integrity of the downloaded VLC installer file by calculating its SHA-256 hash value 
    and comparing it against the expected SHA-256 hash value. 

    Args:
        installer_data (bytes): VLC installer file binary data
        expected_sha256 (str): Expeced SHA-256 of the VLC installer

    Returns:
        bool: True if SHA-256 of VLC installer matches expected SHA-256. False if not.
    """    
    # TODO: Step 3
           
    resp_msg = requests.get(file_url)
    if resp_msg.status_code == requests.codes.ok:
        content_file = resp_msg.content 
        image_hash = hashlib.sha256(content_file).hexdigest()
        return image_hash

    return None


def save_installer(installer_data):
    """Saves the VLC installer to a local directory.

    Args:
        installer_data (bytes): VLC installer file binary data

    Returns:
        str: Full path of the saved VLC installer file
    """
    # TODO: Step 4
    resp_msg = requests.get(file_url)
    if resp_msg.status_code == requests.codes.ok:
        value_of_hash  = get_expected_sha256
        folder = os.getenv('TEMP')
        save_path = os.path.join(folder, 'vlc_installer.exe')
        with open(save_path, 'wb') as file:
            return value_of_hash
    return None 


def run_installer(installer_path):
    """Silently runs the VLC installer.

    Args:
        installer_path (str): Full path of the VLC installer file
    """    
    # TODO: Step 5
    path_installer = r'C:\temp\vlc-3.0.17.4-win64.exe'
    subprocess.run([path_installer, '/L=1033', '/S']) 
    return
    

def delete_installer(installer_path):
    # TODO: Step 6
    # Hint: See example code in lab instructions entitled "Running the VLC Installer"
    """Deletes the VLC installer file.

    Args:
        installer_path (str): Full path of the VLC installer file
    """
    os.remove(file_url)
    return None 

if __name__ == '__main__':
    main()