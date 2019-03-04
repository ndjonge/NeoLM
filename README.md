# NeoLM
license server (expirimental)

WSL(Ubuntu 18.04) steps:

sudo apt-get -y update
sudo apt-get -y install neovim

sudo update-alternatives --install /usr/bin/vi vi /usr/bin/nvim 60
sudo update-alternatives --config vi
sudo update-alternatives --install /usr/bin/vim vim /usr/bin/nvim 60
sudo update-alternatives --config vim
sudo update-alternatives --install /usr/bin/editor editor /usr/bin/nvim 60
sudo update-alternatives --config editor

sudo apt-get -y purge openssh-server
sudo apt-get -y install openssh-server
sudo vi /etc/ssh/sshd_config

#AllowUsers ndjonge
#PasswordAuthentication yes

sudo service ssh --full-restart
sudo apt-get -y install git-core
sudo apt-get -y install zsh
chsh -s $(which zsh)
sh -c "$(curl -fsSL https://raw.github.com/robbyrussell/oh-my-zsh/master/tools/install.sh)"
vi ~/.zshrc
ZSH_THEME="agnoster"

hosts
	127.0.0.1       tls.server.local
	
	
	
	::1             tls.server.local

Openssl:
openssl req \
   -newkey rsa:2048 \
   -x509 \
   -nodes \
   -keyout server.key \
   -new \
   -out server.crt \
   -subj /CN=tls.server.local \
   -reqexts SAN \
   -extensions SAN \
   -config <(cat ./config.cfg \
       <(printf '[SAN]\nsubjectAltName=DNS:tls.server.local')) \
   -sha256 \
   -days 3650

Config:
default_bits        = 2048
distinguished_name  = dn
x509_extensions     = san
req_extensions      = san
extensions          = san
prompt              = no
[ dn ]
countryName         = US
stateOrProvinceName = Massachusetts
localityName        = Boston
organizationName    = MyCompany
[ san ]
subjectAltName      = DNS:tls.server.local

