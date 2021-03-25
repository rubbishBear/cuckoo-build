#!/usr/bin/env bash
# Author madeDurphy

# Declaring color variables
# https://stackoverflow.com/questions/4332478/read-the-current-text-color-in-a-xterm/4332530#4332530
bright=$(tput bold)
green=$(tput setaf 2)
l_yellow=$(tput setaf 190)
normal=$(tput sgr0)
red=$(tput setaf 1)

printf "Cuckoo Install\n"
printf "\n"

# Check if script is being run with sudo permissions
if [[ $UID != 0 ]]; then
        printf "${red}${bright}Please run this script with sudo:${normal}\n"
        printf "sudo $0 $*\n"
        exit 1
fi

# Add repo and run updates
printf "${l_yellow}Adding universe repo...${normal}\n"
sudo apt-add-repository universe
sleep 1
printf ""
printf "${l_yellow}Running updates, upgrade, and removing old packages...${normal}\n"
printf ""
sleep 1
if !(sudo apt-get update && sudo apt-get upgrade --yes && sudo apt-get autoremove --yes); then
    printf "${red}${bright}---- APT Update/Upgrade/Autoremove FAILED ----${normal}\n"
    printf "${red}${bright}-------- Kill all other apt processes --------${normal}\n"
    exit 1
fi

# Preventing prompts during apt install iptables-persistent and wireshark
echo iptables-persistent iptables-persistent/autosave_v4 boolean true | sudo debconf-set-selections
echo iptables-persistent iptables-persistent/autosave_v6 boolean true | sudo debconf-set-selections
echo wireshark-common wireshark-common/install-setuid boolean true | sudo debconf-set-selections

printf "${l_yellow}Installing required packages...${normal}\n"
# Install additional packages
a_pkgs=(
    apparmor-utils
    autoconf
    autotools-dev
    bison
    build-essential
    curl
    cmake
    cpputest
    flex
    freerdp2-dev
    freerdp2-x11
    g++
    gcc
    git
    hwloc
    iptables-persistent
    libavcodec-dev
    libavformat-dev
    libavutil-dev
    libcap2-bin
    libcairo2-dev
    libcmocka-dev
    libdnet-dev
    libdumbnet-dev
    libffi-dev
    libfuzzy-dev
    libhwloc-dev
    libjansson-dev
    libjpeg-turbo8-dev
    libluajit-5.1-dev
    liblzma-dev
    libnet1-dev
    libnetfilter-queue-dev
    libnghttp2-dev
    libmagic-dev
    libmnl-dev
    libpango1.0-dev
    libpcap-dev
    libpcre3-dev
    libpq-dev
    libpng16-16
    libpulse-dev
    libsqlite3-dev
    libssh2-1-dev
    libossp-uuid-dev
    libssl-dev
    libswscale-dev
    libtelnet-dev
    libtool-bin
    libunwind-dev
    libvncserver-dev
    libvorbis-dev
    libwebp-dev
    libwebsockets-dev
    luajit
    make
    mlocate
    mongodb
    net-tools
    nginx
    openjdk-11-jdk
    openssl
    pcregrep
    postgresql
    pkg-config
    python
    python-dev
    python-setuptools
    p7zip-full
    ssdeep
    swig
    terminator
    tcpdump
    tomcat9
    tomcat9-admin
    tomcat9-common
    tomcat9-user
    uuid-dev
    vim
    virtualbox
    wireshark
    yara
    zlib1g-dev
)

# https://unix.stackexchange.com/questions/447277/how-to-align-multiple-lines-with-printf-or-print
for apt_pkg in ${a_pkgs[@]}; do
    printf "%-65s %s" "Installing ${apt_pkg}..."
    if [[ $(sudo dpkg --list | awk '{print $2}' | egrep "^${apt_pkg}$" 2>/dev/null) == ${apt_pkg} ]]; then
        printf "${l_yellow}#### INSTALLED ####${normal}\n"
    elif (sudo apt-get install -y ${apt_pkg} -qq > /dev/null 2>&1); then
        printf "${green}++++ SUCCESS ++++${normal}\n"
    else
        printf "${red}${bright}---- FAILED ----${normal}\n"
    fi
done

# Add current user to groups
printf "${l_yellow}Creating the 'pcap' group...${normal}\n"
sudo groupadd pcap
printf "${l_yellow}Creating the 'snort' group...${normal}\n"
sudo groupadd snort
printf "${l_yellow}Changing group for '/usr/sbin/tcpdump' to 'pcap'...${normal}\n"
sudo chgrp pcap /usr/sbin/tcpdump

groups=(
    pcap
    snort
    vboxusers
)

for grp in ${groups[@]}; do
    printf "${l_yellow}Adding $SUDO_USER to the '$grp' group...${normal}\n"
    sudo usermod -a -G $grp $SUDO_USER
done

# Changing profile picture
curl -sSL 'https://avatars.githubusercontent.com/u/1032683?s=400&v=4' --output /home/$SUDO_USER/.face

# Download and install pip
printf "%-65s %s" "${l_yellow}Downloading Pip 2.7${normal}"
sleep 5
curl -sSL https://bootstrap.pypa.io/pip/2.7/get-pip.py --output /tmp/get-pip.py
if [[ -e /tmp/get-pip.py ]]; then
    printf "${green}++++ SUCCESS ++++${normal}\n"
    sudo python /tmp/get-pip.py
    # Check for successful install
    if python -m pip --version | grep -E "\(python\s2\.7\)$" > /dev/null; then
        printf "\n%-65s %s" "${l_yellow}Installing Pip 2.7${normal}"
        printf "${green}++++ SUCCESS ++++${normal}\n"
        rm /tmp/get-pip.py
    else
        printf "\n%-65s %s" "${l_yellow}Installing Pip 2.7${normal}"
        printf "${red}${bright}---- FAILED ----${normal}\n"
        printf "${red}${bright}---- Pip 2.7 is required in order to install other required pip packages, exiting now ----${normal}\n"
        exit 1
    fi
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
    printf "${red}${bright}---- Pip 2.7 is required in order to install other required pip packages, exiting now ----${normal}\n"
    exit 1
fi

# Installing Guacamole from source
cpus=$(( $(lscpu | grep -P "^CPU\(s\):" | awk '{print $NF}') - 1))
mkdir /tmp/guac-build
printf "%-65s %s" "${l_yellow}Downloading Guacamole Server${normal}"
sleep 5
curl -sSL http://mirror.cc.columbia.edu/pub/software/apache/guacamole/1.3.0/source/guacamole-server-1.3.0.tar.gz --output /tmp/guac-build/guacamole-server-1.3.0.tar.gz
if [[ -e /tmp/guac-build/guacamole-server-1.3.0.tar.gz ]]; then
    printf "${green}++++ SUCCESS ++++${normal}\n"
    sudo tar -xvf /tmp/guac-build/guacamole-server-1.3.0.tar.gz --directory=/opt/ 2>&1 > /dev/null
    if (cd /opt/guacamole-server-1.3.0 && sudo ./configure --with-init-dir=/etc/init.d && sudo make -j $cpus && sudo make install -j $cpus); then
        sudo ldconfig
        sudo /etc/init.d/guacd start
        printf "%-65s %s\n" "${l_yellow}Installing Guacamole Server${normal}" "${green}++++ SUCCESS ++++${normal}"
        rm -rf /tmp/guac-build/
    else
        printf "%-65s %s\n" "${l_yellow}Installing Guacamole Server${normal}" "${red}${bright}--- FAILED ----${normal}"
    fi
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
    rm -rf /tmp/guac-build/
fi

# Installing Snort2 from source
# https://upcloud.com/community/tutorials/install-snort-ubuntu/
mkdir /home/$SUDO_USER/snort-source-files
printf "%-65s %s" "${l_yellow}Downloading Daq${normal}"
sleep 5
curl -sSL https://snort.org/downloads/snort/daq-2.0.7.tar.gz --output /tmp/daq-2.0.7.tar.gz
if [[ -e /tmp/daq-2.0.7.tar.gz ]]; then    
    printf "${green}++++ SUCCESS ++++${normal}\n"
    sudo tar -xvf /tmp/daq-2.0.7.tar.gz --directory=/home/$SUDO_USER/snort-source-files/
    if (cd /home/$SUDO_USER/snort-source-files/daq-2.0.7 && sudo ./configure && sudo make -j $cpus && sudo make install -j $cpus); then
        printf "%-65s %s\n" "${l_yellow}Installing DAQ ${normal}" "${green}++++ SUCCESS ++++${normal}"
        rm /tmp/daq-2.0.7.tar.gz
    else
        printf "%-65s %s\n" "${l_yellow}Installing DAQ${normal}" "${red}${bright}---- FAILED ----${normal}"
    fi
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi

printf "%-65s %s" "${l_yellow}Downloading Snort2${normal}"
sleep 5
curl -sSL https://www.snort.org/downloads/snort/snort-2.9.17.tar.gz --output /tmp/snort-2.9.17.tar.gz
if [[ -e /tmp/snort-2.9.17.tar.gz ]]; then
    printf "${green}++++ SUCCESS ++++${normal}\n"
    sudo tar -xvf /tmp/snort-2.9.17.tar.gz --directory=/home/$SUDO_USER/snort-source-files/
    if (cd /home/$SUDO_USER/snort-source-files/snort-2.9.17 && sudo ./configure --enable-sourcefire && sudo make -j $cpus && sudo make install -j $cpus); then
        printf "%-65s %s\n" "${l_yellow}Installing Snort2${normal}" "${green}++++ SUCCESS ++++${normal}"
        sudo ldconfig
        sudo ln -s /usr/local/bin/snort /usr/sbin/snort
        rm /tmp/snort-2.9.17.tar.gz
    else
        printf "%-65s %s\n" "${l_yellow}Installing Snort2${normal}" "${red}${bright}---- FAILED ----${normal}"
    fi
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi

sudo mkdir -p /etc/snort/rules
sudo mkdir /var/log/snort
sudo mkdir /usr/local/lib/snort_dynamicrules
sudo touch /etc/snort/rules/white_list.rules
sudo touch /etc/snort/rules/black_list.rules
sudo touch /etc/snort/rules/local.rules
sudo cp /home/$SUDO_USER/snort-source-files/snort-2.9.17/etc/*.conf* /etc/snort
sudo cp /home/$SUDO_USER/snort-source-files/snort-2.9.17/etc/*.map /etc/snort

printf "%-65s %s" "${l_yellow}Downloading Snort community rules${normal}"
curl -sSL https://www.snort.org/downloads/community/community-rules.tar.gz --output /tmp/community-rules.tar.gz
if [[ -e /tmp/community-rules.tar.gz ]]; then
    print "${green}++++ SUCCESS ++++${normal}\n"
    sudo tar -xvf /tmp/community-rules.tar.gz --directory=/etc/snort/rules
    sudo sed -i 's/include \$RULE\_PATH/#include \$RULE\_PATH/' /etc/snort/snort.conf
    rm /tmp/community-rules.tar.gz
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi

# Installing Yara from source
mkdir /tmp/yara
printf "%-65s %s" "${l_yellow}Downloading Yara${normal}"
curl -sSL https://github.com/VirusTotal/yara/archive/v4.0.5.tar.gz --output /tmp/yara/v4.0.5.tar.gz
if [[ -e /tmp/yara/v4.0.5.tar.gz ]]; then
    printf "${green}++++ SUCCESS ++++${normal}\n"
    sudo tar -xvf /tmp/yara/v4.0.5.tar.gz --directory=/home/$SUDO_USER
    if (cd /home/$SUDO_USER/yara-4.0.5 && sudo ./bootstrap.sh && sudo ./configure --enable-cuckoo --enable-magic --with-crypto && sudo make -j $cpus && sudo make install -j $cpus && sudo make check); then
        printf "%-65s %s\n" "${l_yellow}Installing Yara${normal}" "${green}++++ SUCCESS ++++${normal}"
        rm -rf /tmp/yara
    else
        printf "%-65s %s\n" "${l_yellow}Installing Yara${normal}" "${red}${bright}---- FAILED ----${normal}"
    fi
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi

# Install Volatility2 from source
printf "%-65s %s" "${l_yellow}Downloading Volatility${normal}"
if sudo git clone -q https://github.com/volatilityfoundation/volatility.git /opt/volatility > /dev/null 2>&1; then
    printf "${green}++++ SUCCESS ++++${normal}\n"
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi
printf "%-65s %s" "${l_yellow}Downloading Volatility community plugins${normal}"
if sudo git clone https://github.com/volatilityfoundation/community.git /opt/volatility/volatility/contrib > /dev/null 2>&1; then
    printf "${green}++++ SUCCESS ++++${normal}\n"
    if (cd /opt/volatility && sudo python ./setup.py install); then
        printf "%-65s %s\n" "${l_yellow}Installing Volatility and community plugins" "${green}++++ SUCCESS ++++${normal}"
    else
        printf "%-65s %s\n" "${l_yellow}Installing Volatility and community plugins" "${red}${bright}---- FAILED ----${normal}"
    fi
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi

# Install Elasticsearch
curl -sSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo apt-key add
echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-7.x.list
printf "%-65s %s" "${l_yellow}Installing Elasticsearch...${normal}" 
if (sudo apt-get update && sudo apt-get install -y elasticsearch -qq > /dev/null 2>&1); then
    printf "${green}++++ SUCCESS ++++${normal}\n"
    sudo /bin/systemctl daemon-reload
    sudo /bin/systemctl enable elasticsearch.service
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi

# Other PIP installs
pip_pkgs=(
    pip
    setuptools
    ansible
    jupyter
    lxml
    openpyxl
    Pillow
    pycrypto
    pydeep
    ujson
    cybox==2.0.1.4
    "Django<2"
    distorm3==3.4.4
    maec==4.0.1.0
    IPython==5.0
    yara-python
    cuckoo
)

for p_pkg in ${pip_pkgs[@]}; do
    printf "%-65s %s" "${l_yellow}Installing ${p_pkg}...${normal}"
    if sudo -H pip install -U ${p_pkg}; then
        printf "%-65s %s\n" "${l_yellow}Installing ${p_pkg}...${normal}" "${green}++++ SUCCESS ++++${normal}"
    else
        printf "%-65s %s\n" "${l_yellow}Installing ${p_pkg}...${normal}" "${red}${bright}---- FAILED ----${normal}"
    fi
done

# Allow creation of pcap in CWD - Cuckoo Working Directory
sudo aa-disable /usr/sbin/tcpdump
sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump

# Verify the setcap command
if [[ $(getcap /usr/sbin/tcpdump) == "/usr/sbin/tcpdump = cap_net_admin,cap_net_raw+eip" ]]; then
        printf "${green}TCPDump settings Success!${normal}\n"
else
        printf "${red}${bright}Please check TCPDump settings by runnning \"sudo setcap cap_net_raw,cap_net_admin=eip /usr/sbin/tcpdump\"\n${normal}"
fi

if [[ -e /usr/local/bin/cuckoo ]]; then
    printf "${green}Cuckoo has been successfully installed...${normal}"
else    
    printf "${red}${bright}Cuckoo Install - something went wrong.${normal}"
fi

# Create default directory for Cuckoo
cuckoo && printf "%-65s %s\n" "${l_yellow}Creating Cuckoo default directory${normal}" "${green}++++ SUCCESS ++++"

# Install VirtualBox Extension pack
printf "%-65s %s" "${l_yellow}Downloading VirtualBox Extension Pack${normal}"
curl -sSL https://download.virtualbox.org/virtualbox/6.1.18/Oracle_VM_VirtualBox_Extension_Pack-6.1.18.vbox-extpack --output /tmp/Oracle_VM_VirtualBox_Extension_Pack-6.1.18.vbox-extpack
if [[ -e /tmp/Oracle_VM_VirtualBox_Extension_Pack-6.1.18.vbox-extpack ]]; then
    printf "${green}++++ SUCCESS ++++${normal}\n"
    if (printf y | sudo VBoxManage extpack install --replace /tmp/Oracle_VM_VirtualBox_Extension_Pack-6.1.18.vbox-extpack); then
        printf "%-65s %s\n" "${l_yellow}Installing VirtualBox Extension Pack${normal}" "${green}++++ SUCCESS ++++${normal}"
        rm /tmp/Oracle_VM_VirtualBox_Extension_Pack-6.1.18.vbox-extpack
    else
        printf "%-65s %s\n" "${l_yellow}Installing VirtualBox Extension Pack${normal}" "${red}${bright}---- FAILED ----${normal}"
    fi
else
    printf "${red}${bright}---- FAILED ----${normal}\n"
fi

# Configure virtual NICs for VirtualBox
printf "${l_yellow}Configuring hostonly nic for VirtualBox...${normal}\n"
printf "${l_yellow}Gateway will be set to 192.168.56.1${normal}\n"
vboxmanage hostonlyif create
vboxmanage hostonlyif ipconfig vboxnet0 --ip 192.168.56.1

# Configure iptables to allow guest connectivity to the internet
printf "${l_yellow}Configuring iptables...${normal}\n"
sudo iptables -A FORWARD -o ens33 -i vboxnet0 -s 192.168.56.0/24 -m conntrack --ctstate NEW -j ACCEPT
sudo iptables -A FORWARD -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
sudo iptables -A POSTROUTING -t nat -o ens33 -j MASQUERADE
printf 1 | sudo tee -a /proc/sys/net/ipv4/ip_forward > /dev/null
sudo sysctl -w net.ipv4.ip_forward=1 > /dev/null
sudo sed -i "s/^#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/" /etc/sysctl.conf
sudo iptables-save > /etc/iptables/rules.v4

# Create the vbox nic service
svcfile=/etc/systemd/system/vboxhostonlynic.service
sudo cat <<EOF > $svcfile
[Unit]
Description=Setup VirtualBox Hostonly Adapter
After=vboxdrv.service

[Service]
Type=oneshot
ExecStart=/usr/bin/vboxmanage hostonlyif create
ExecStart=/usr/bin/vboxmanage hostonlyif ipconfig vboxnet --ip 192.168.56.1
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
sudo chmod +x $svcfile

printf "${l_yellow}Service successfully created, reloading daemons and enabling service...${normal}\n"
sudo systemctl daemon-reload
sudo systemctl enable vboxhostonlynic.service
sudo /lib/systemd/systemd-sysv-install enable guacd
sudo systemctl start guacd
sudo systemctl start snort3-nic.service
