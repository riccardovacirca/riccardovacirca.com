
all:
	gcc -std=gnu99 -fPIC -shared -I. -I.. -I/usr/include/apr-1.0 -I/usr/include/apache2 \
	-o mod_ns_session.so ../ns_utils.c ns_session.c mod_ns_session.c -lapr-1 -laprutil-1

install:
	mkdir -p /var/www/html/ns && cp index.html /var/www/html/ns/index.html
	cp mod_ns_session.so /usr/lib/apache2/modules/mod_ns_session.so
	cp ns_vhost.conf /etc/apache2/sites-available/ns_vhost.conf
	cp ns_session.load /etc/apache2/mods-available/ns_session.load
	cp ns_session.conf /etc/apache2/mods-available/ns_session.conf
	a2ensite ns_vhost
	a2enmod session session_cookie session_crypto ns_session
	systemctl stop apache2
	apachectl -DFOREGROUND

uninstall:
	a2dismod session_crypto session_cookie session ns_session
	a2dissite ns_vhost
	rm -rf /usr/lib/apache2/modules/mod_ns_session.so
	rm -rf /etc/apache2/sites-available/ns_vhost.conf
	rm -rf /etc/apache2/mods-available/ns_session.load
	rm -rf /etc/apache2/mods-available/ns_session.conf
	rm -rf /var/www/html/ns
	systemctl start apache2

test:
	curl -i -c /tmp/ns_cookie.txt -b /tmp/ns_cookie.txt -X GET \
	"http://ns.example.com/ssn"

.PHONY: all install uninstall test
