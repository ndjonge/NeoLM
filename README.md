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


