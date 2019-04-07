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

docker run -d --name kong-database --network=kong-net -p 5432:5432 -e “POSTGRES_USER=kong” -e “POSTGRES_DB=kong” "POSTGRES_PASSWORD=kong" postgres 
docker run -d --name kong-database --network=kong-net -p 5432:5432 -e “POSTGRES_USER=kong” -e “POSTGRES_DB=kong” postgres
docker run --rm --network=kong-net -e "KONG_DATABASE=postgres" -e "KONG_PG_HOST=kong-database" -e "KONG_PG_PASSWORD=kong" kong:latest kong migrations up
docker run -d --name kong --network=kong-net -e "KONG_DATABASE=postgres" -e "KONG_PG_HOST=kong-database" -e "KONG_PROXY_ACCESS_LOG=/dev/stdout" -e "KONG_ADMIN_ACCESS_LOG=/dev/stdout" -e "KONG_PROXY_ERROR_LOG=/dev/stderr" -e "KONG_ADMIN_ERROR_LOG=/dev/stderr" -e "KONG_ADMIN_LISTEN=0.0.0.0:8001, 0.0.0.0:8444 ssl" -p 8000:8000 -p 8443:8443 -p 8001:8001 -p 8444:8444 kong:latest
docker run -d --name kong --network=kong-net --link kong-database:kong-database -e "KONG_DATABASE=postgres" -e "KONG_PG_HOST=kong-database" -p 8000:8000 -p 8443:8443 -p 8001:8001 -p 8444:8444 kong