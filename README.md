# Building A Cuckoo Sandbox

"There are many like it, but this one is mine."

To some, building a [Cuckoo](https://cuckoosandbox.org) sandbox can be painful. This script was made to be an easy button for those who want to go straight to analyzing malware.

## Build Requirements

- [ ] Ubuntu 20.04 LTS
- [ ] Windows ISO\*

This script was made specifically for Ubuntu 20.04 LTS and has not been tested on any other version. If you are running Cuckoo in a VM using a VM "inception" concept, enable virtualization for the VM's processor.

\*Any OS can be used for your analysis VM however for these instructions we will be using Windows 7 x64 SP1.

# Using The Script

Assuming you are starting from a vanilla install of Ubuntu 20.04, make sure a software update is not pending - it may prevent the script from executing.

Run the script using `sudo` from the home directory as follows:

`$ sudo ./cuckoo_install.sh`

The script will take some time to finish.

# Post Install Configuration

Once the script has finished, you can start creating the analysis VM and edit the cuckoo config files.

## Creating the Analysis VM

Copy the Windows ISO (Win 7 x64 SP1) over to your Cuckoo box.

Create a new virtual machine in VirtualBox. Adjust these settings as needed:

- Name - cuckoo1\*
- Processors - 4
- RAM - 4 GB
- HDD - 100 GB
- Disk Type - VMDK
- Storage - Dynamically Allocated

\*The names in the config files and the VM must match.

Set your VM's network adapter to Host-only using vboxnet0. You may still have to create vboxnet0 if it doesn't reappear. Within VirtualBox go to File -> Host Network Manager -> Create.

Once your analysis vm has been created, proceed with the normal installation for Windows 7.

**NOTE:** During the setup under "...Improve Windows automatically", choose "Ask me later".

## Configuring Analysis VM Network Settings

Configure these network adapter settings:

- IP - 192.168.56.xxx\*
- SM - 255.255.255.0
- DG - 192.168.56.1
- DNS 1 - 1.1.1.1
- DNS 2 - 1.0.0.1

\*Replace the 'xxx' with the last octet of your choice.

## Configuring Vulnerability Settings

After Windows 7 has been installed, you will configure it to be intentionally vulnerable.

Within group policy editor (gpedit.msc):
  - Computer Configuration -> Administrative Templates -> Windows Components -> Windows Updates -> Configure automatic updates -> Enabled, Notify for download and notify for install
  - Computer Configuration -> Administrative Templates -> Windows Components -> Windows Defender Antivirus -> Turn off Windows Defender Antivirus -> Enabled
  - Computer Configuration -> Administrative Templates -> Network -> Network connections -> Windows Firewall -> Domain Profile -> Windows Firewall: Protect all network connections -> Disabled
  - Computer Configuration -> Windows Settings -> Security Settings -> Local Policies -> Security Options -> User Account Control: Behavior of the elevation prompt for administrators in Admin Approval Mode -> Elevate without prompting
    - User Account Control: Detect application installations and prompt for elevation -> Disabled
    - User Account Control: Run all administrators in Admin Approval Mode -> Disabled

## Additional Installations for Analysis VM

### Install VBox Guest Additions
Although not necessary, installing VBox Guest Additions conveniently allows you to move other necessary files to your analysis VM. The same effect can be achieved by using SMB via smbclient (or your method of choice) however it may be easier to just install VBox guest additions. Keep in mind, some malware may contain anti-analysis measures to include checking if it's running in a VM (by looking for the VBox guest additions).

VBox Guest Additions can be found [here](https://download.virtualbox.org/virtualbox/6.1.16/VBoxGuestAdditions_6.1.16.iso). Once it's been downloaded, attach the ISO to your analysis VM. Navigate to the disk and run the appropriate installer.

### Install Python 2.7
The MSI install file can be found [here](https://www.python.org/ftp/python/2.7.18/python-2.7.18.amd64.msi). Copy over the installer to your analysis VM. Run the install and choose "Install for all users" then accept all other defaults.

### Install Python Pillow
Download and install python pillow. The installation file can be found [here](https://pypi.python.org/packages/2.7/P/Pillow/Pillow-2.5.3.win-amd64-py2.7.exe). The MD5 sum is 33c3a581ff1538b4f79b4651084090c8. Copy it over to your analysis VM and run the install.

### Install Misc applications
Provide any other functionality to your analysis VM by downloading and installing other vulnerable applications. This may include Adobe Reader for analyzing malicious PDFs,  Office for Word/Excel/PowerPoint, Chrome/Firefox, etc.

**NOTE:** Older versions of Adobe can be found ftp://ftp.adobe.com/pub/adobe/reader/win/.

### The Cuckoo Python Agent
The Cuckoo Python agent needs to be uploaded to your analysis VM. The file can be found at `~/.cuckoo/agent/agent.py`. The file must be placed in your analysis VM in:
`C:\Users\%USERNAME%\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup`.

**NOTE:** If you can't find the CWD (Cuckoo Working Directory), it may not have been created. Run `cuckoo` in the terminal with no arguments to create the `~/.cuckoo` directory.

After the above is completed, perform a restart on the analysis VM. Once it starts back up, a command prompt should appear in the background. If you get a Windows Security Alert, go ahead and allow the agent.

## Creating the Snapshot

**IMPORTANT:** While the VM is running (yes, powered on and running), take a snapshot and name it 'Snapshot1'. Once the snapshot is taken, you can power off your VM.

# Editing the Config Files

Back in Ubuntu, there are config files you'll need to edit. They are all located in `/home/$USER/.cuckoo/conf`.

`auxiliary.conf`:
- [sniffer]
  -`enabled = yes`

`cuckoo.conf`:
- `machinery = virtualbox`
- `memory_dump = yes`
- [resultserver]
  - `ip = 192.168.56.1`
- [remotecontrol]
  - `enabled = yes`

`memory.conf`:
- [basic]
  - `guest_profile = Win7SP1x64`\*

`processing.conf`:
- [memory]
  - `enabled = yes`
- [snort]
  - `enabled = yes`
- `snort = /usr/local/bin/snort`
- `conf = /etc/snort/snort.conf`
 
`reporting.conf`:
- [singlefile]
  - `enabled = yes`
- [mongodb]
  - `enabled = yes`

`virtualbox.conf`:
- `mode = gui`
- `interface = vboxnet0`
- [cuckoo1]
  - `machines = cuckoo1`\*\*
- `snapshot = Snapshot1`
- `ip = 192.168.56.xxx`\*\*\*

\*The `guest_profile` setting may vary depending on your choice of OS for the analysis VM. Verify your guest profile for Volatility for the OS you are using and place that here.

\*\*The machine name within the brackets (in this case `[cuckoo1]`) must match the machine name in VirtualBox as well as the name`machines` setting.

\*\*Replace the 'xxx' with the last octet of the IP address you assigned to your analysis VM.

# Cuckoo Functionality

## Snort
The current version of Cuckoo is configured to work with Snort2. The install script has been configured to download the snort community rules and extract them to `/etc/snort/rules`. Modify the snort config file (`/etc/snort/snort.conf`) as necessary per Snort documentation.
 
## Elasticsearch and Guacamole
The install script has been set up to download and install Elasticsearch and Guacamole. However, there are known issues with the current version of Cuckoo working with Elasticsearch 7.x due to (what my understanding is) variations with the JSON template. There are also known issues with Guacamole connecting to the analysis VM to provide user interaction with the malware.

## Yara
Follow Yara documentation for importing rules.

# Using Cuckoo

Once all the above is complete, from the terminal run `cuckoo community` to download the scoring signatures.

## Cuckoo Analysis
To begin analysis, open up terminator (has been included with the install script) and VirtualBox. To provide visibility of analysis activity, split your terminator window into four panels. It's recommended to run the following commands in the same order to start cuckoo:

- Window 1: `$ vboxmanage snapshot "[vm name]" restore current` -> This restores the analysis VM back to the snapshot that was taken **while the machine was running**.
  - `$ cuckoo web runserver` -> This will start the Cuckoo web server and provide feedback on what the web server is doing.             
  - `$ cuckoo web runserver 0.0.0.0:8000` -> Starting the Cuckoo web server in this manner will have cuckoo listen for web connections from any IP across the network.
- Window 2: `$ cuckoo` -> This starts cuckoo as a whole. The window can be used to monitor the progress of analysis.
- Window 3: `$ cuckoo -d process a2` -> This will display debug messages from Cuckoo providing verbose messaging letting you know the analysis is still processing and if Cuckoo has run into any errors
- Window 4: Can be used to submit a file for analysis or execute any other commands in the terminal. See [Cuckoo documentation](https://cuckoo.readthedocs.io/en/latest/) for submitting to/interacting with Cuckoo via the terminal.

After Cuckoo has been started through the terminal you can open up a browser window and navigate to localhost:8000. If you are trying to reach Cuckoo from over the network, ensure you've started the web server with `$ cuckoo run webserver 0.0.0.0:8000` and navigate to Cuckoo's IP address using port 8000.

**Cuckoo is now ready, happy analyzing!**
