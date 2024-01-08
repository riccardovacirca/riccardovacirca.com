
all:
	gcc -std=gnu99 -fPIC -shared -I/usr/include/apr-1.0 -I/usr/include/apache2 \
	-o mod_ns_cookies.so mod_ns_cookies.c -lapr-1 -laprutil-1

install:
	mkdir -p /var/www/html/ns && cp index.html /var/www/html/ns/index.html
	cp mod_ns_cookies.so /usr/lib/apache2/modules/mod_ns_cookies.so
	cp ns_vhost.conf /etc/apache2/sites-available/ns_vhost.conf
	cp ns_cookies.load /etc/apache2/mods-available/ns_cookies.load
	cp ns_cookies.conf /etc/apache2/mods-available/ns_cookies.conf
	a2ensite ns_vhost
	a2enmod dbd authn_dbd ns_cookies
	systemctl stop apache2
	apachectl -DFOREGROUND

uninstall:
	a2dismod ns_cookies
	a2dissite ns_vhost
	rm -rf /usr/lib/apache2/modules/mod_ns_cookies.so
	rm -rf /etc/apache2/sites-available/ns_vhost.conf
	rm -rf /etc/apache2/mods-available/ns_cookies.load
	rm -rf /etc/apache2/mods-available/ns_cookies.conf
	rm -rf /var/www/html/ns
	systemctl start apache2

test:
	curl -i -c /tmp/ns_cookie.txt -b /tmp/ns_cookie.txt -X GET \
	"http://ns.example.com/cookies"

.PHONY: all install uninstall password test
