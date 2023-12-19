
all:
	gcc -std=gnu99 -fPIC -shared -I/usr/include/apr-1.0 -I/usr/include/apache2 \
	-o mod_wm_session.so mod_wm_session.c -lapr-1 -laprutil-1

install:
	mkdir -p /var/www/html/wm && cp index.html /var/www/html/wm/index.html
	cp mod_wm_session.so /usr/lib/apache2/modules/mod_wm_session.so
	cp wm_vhost.conf /etc/apache2/sites-available/wm_vhost.conf
	cp wm_session.load /etc/apache2/mods-available/wm_session.load
	cp wm_session.conf /etc/apache2/mods-available/wm_session.conf
	a2ensite wm_vhost
	a2enmod session session_cookie wm_session
	systemctl stop apache2
	apachectl -DFOREGROUND

uninstall:
	a2dismod authn_dbd dbd wm_session
	a2dissite wm_vhost
	rm -rf /usr/lib/apache2/modules/mod_wm_session.so
	rm -rf /etc/apache2/sites-available/wm_vhost.conf
	rm -rf /etc/apache2/mods-available/wm_session.load
	rm -rf /etc/apache2/mods-available/wm_session.conf
	rm -rf /var/www/html/wm
	systemctl start apache2

test:
	curl -H "Authorization: Basic Ym9iOnNlY3JldA==" -i "http://wm.example.com/auth"

.PHONY: all install uninstall test
