#!/bin/sh

#Download installation files
cd /home/jamiecoupe
#Requiremenrs: openssl-1.0.1e.tar.gz, httpd-2.4.25.tar.gz, apr-1.5.2.tar.gz, 
#apr-util-1.5.4.tar.gz, pcre-8.40.tar.gz into your home directory.

#Install pcre
apt-get install libpcre3-dev
cd /home/jamiecoupe
tar -zxvf pcre-8.40.tar.gz
cd pcre-8.40
./configure --prefix=/usr/local/pcre-config
make
make install

#Install openssl
cd /home/jamiecoupe
tar -zxvf openssl-1.0.1e.tar.gz
cd openssl-1.0.1e
./config     --prefix=/opt/openssl-1.0.1e     --openssldir=/opt/openssl-1.0.1e -fPIC -DOPENSSL_PIC
make
make install_sw

#Install httpd 
cd /home/jamiecoupe
tar -zxvf httpd-2.4.25.tar.gz
cd httpd-2.4.25/srclib/
tar zxvf ../../apr-1.5.2.tar.gz
ln -s apr-1.5.2/ apr
tar zxvf ../../apr-util-1.5.4.tar.gz
ln -s apr-util-1.5.4/ apr-util
cd /home/jamiecoupe
cd httpd-2.4.25
./configure     --prefix=/opt/httpd     --with-included-apr     --enable-ssl     --with-ssl=/opt/openssl-1.0.1e --enable-ssl-staticlib-deps     --enable-mods-static=ssl --with-pcre=/usr/local/pcre-config
make
make install

#Add configuration to use HTTPS (port 443)
cd /home/jamiecoupe
sed -i '/^#.*Include conf\/extra\/httpd-ssl.conf/s/^#//' /opt/httpd/conf/httpd.conf
sed -i '/^#.*LoadModule socache_shmcb_module modules\/mod_socache_shmcb.so/s/^#//' /opt/httpd/conf/httpd.conf

cd /home/jamiecoupe
openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /opt/httpd/conf/server.key -out /opt/httpd/conf/server.crt -subj "/C=UK/ST=Scotland/L=Glasgow/O=Project/OU=SSLUnit/CN=172.16.241.132"

/opt/httpd/bin/apachectl start

iptables -F

#Remove downloaded files
cd /home/jamiecoupe
rm -rf ~/openssl-1.0.1

rm -rf ~/httpd

rm -rf ~/pcre
