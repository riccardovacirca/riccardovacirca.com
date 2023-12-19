
all:
	gcc -std=gnu99 -fPIC -shared -I/usr/include/apr-1.0 -I/usr/include/apache2 \
	-o mod_wm_auth.so mod_wm_auth.c -lapr-1 -laprutil-1

install:
	mkdir -p /var/www/html/wm && cp index.html /var/www/html/wm/index.html
	cp mod_wm_auth.so /usr/lib/apache2/modules/mod_wm_auth.so
	cp wm_auth_vhost.conf /etc/apache2/sites-available/wm_auth_vhost.conf
	cp wm_auth.load /etc/apache2/mods-available/wm_auth.load
	cp wm_auth.conf /etc/apache2/mods-available/wm_auth.conf
	a2ensite wm_auth_vhost
	a2enmod dbd authn_dbd wm_auth
	systemctl stop apache2
	apachectl -DFOREGROUND

uninstall:
	a2dismod authn_dbd dbd wm_auth
	a2dissite wm_auth_vhost
	rm -rf /usr/lib/apache2/modules/mod_wm_auth.so
	rm -rf /etc/apache2/sites-available/wm_auth_vhost.conf
	rm -rf /etc/apache2/mods-available/wm_auth.load
	rm -rf /etc/apache2/mods-available/wm_auth.conf
	rm -rf /var/www/html/wm
	systemctl start apache2

password:
	@php password.php

test:
	curl -H "Authorization: Basic Ym9iOnNlY3JldA==" -i "http://wm.example.com/auth"

.PHONY: all install uninstall password test
