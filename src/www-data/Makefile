
APACHE_SYSSITEDIR=`apxs -q SYSCONFDIR`/sites-available

all:
	@echo "Use: make install"

install: server-install client-install
	service apache2 restart

uninstall: server-uninstall client-uninstall
	service apache2 restart

server-install:
	mkdir -p /var/www/html/server/log
	cp server-index.php /var/www/html/server/index.php
	cp server-htaccess /var/www/html/server/.htaccess
	cp server-vhost.conf $(APACHE_SYSSITEDIR)/server-vhost.conf
	cp server-passwd /var/www/html/server/passwd
	cp hello.txt /var/www/html/server/hello.txt
	cp *.pem /var/www/html/server
	chown -R www-data:www-data /var/www/html/server/passwd
	chmod 600 /var/www/html/server/private_key.pem
	chmod 600 /var/www/html/server/public_key.pem
	a2enmod rewrite headers
	a2ensite server-vhost.conf

server-uninstall:
	a2dissite server-vhost.conf
	rm -rf $(APACHE_SYSSITEDIR)/server-vhost.conf
	rm -rf /var/www/html/server

client-install:
	mkdir -p /var/www/html/client
	cp client-index.php /var/www/html/client/index.php
	cp qrcode.html /var/www/html/client/qrcode.html
	cp client-htaccess /var/www/html/client/.htaccess
	cp client-vhost.conf $(APACHE_SYSSITEDIR)/client-vhost.conf
	a2enmod rewrite headers
	a2ensite client-vhost.conf

client-uninstall:
	a2dissite client-vhost.conf
	rm -rf $(APACHE_SYSSITEDIR)/client-vhost.conf
	rm -rf /var/www/html/client

test:
	curl -i -X GET "http://server.local"
	curl -i -X GET "http://client.local"
