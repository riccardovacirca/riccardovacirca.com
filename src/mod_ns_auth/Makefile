
all:
	gcc -std=gnu99 -fPIC -shared -I/usr/include/apr-1.0 -I/usr/include/apache2 \
	-o mod_ns_auth.so mod_ns_auth.c -lapr-1 -laprutil-1

install:
	mkdir -p /var/www/html/ns && cp index.html /var/www/html/ns/index.html
	cp mod_ns_auth.so /usr/lib/apache2/modules/mod_ns_auth.so
	cp ns_vhost.conf /etc/apache2/sites-available/ns_vhost.conf
	cp ns_auth.load /etc/apache2/mods-available/ns_auth.load
	cp ns_auth.conf /etc/apache2/mods-available/ns_auth.conf
	a2ensite ns_vhost
	a2enmod dbd authn_dbd ns_auth
	systemctl stop apache2
	apachectl -DFOREGROUND

uninstall:
	a2dismod authn_dbd dbd ns_auth
	a2dissite ns_vhost
	rm -rf /usr/lib/apache2/modules/mod_ns_auth.so
	rm -rf /etc/apache2/sites-available/ns_vhost.conf
	rm -rf /etc/apache2/mods-available/ns_auth.load
	rm -rf /etc/apache2/mods-available/ns_auth.conf
	rm -rf /var/www/html/ns
	systemctl start apache2

password:
	@php password.php

test:
	curl -H "Authorization: Basic Ym9iOnNlY3JldA==" -i "http://ns.example.com/auth"

.PHONY: all install uninstall password test
