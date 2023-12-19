# 	----------------------------------------------------------------------------
#
#		ZET - Zero-overhead Extension Tools
# 	Example Makefile
#
# 	Copyright (c)2023 Riccardo Vacirca <rvacirca23@gmail.com>
#
# 	----------------------------------------------------------------------------

LANG   	:= cpp
NAME   	:= z_cookies
VERS   	:= 0.0.1
DIRS   	:= src
EXTS   	:= .c .cpp

HANDLE	:= cookies
MODULE	:= mod_$(NAME).so

# ----------------
# COMPILER OPTIONS
# ----------------

EXTRA_CFLAGS		:=-D_ZET_HAS_JSON -D_ZET_HAS_SSL -D_ZET_HAS_AUTH -D_ZET_HAS_APACHE
EXTRA_INCLUDES	:=-I/usr/include/apache2 -I/usr/include/openssl \
									-I/usr/include/json-c
EXTRA_LIBS			:=
EXTRA_LDFLAGS		:=-lssl -lcrypto -ljson-c

# ------------------------
# COMPILER GENERAL OPTIONS
# ------------------------

GCC				:=gcc -std=gnu99
GPP				:=g++ -std=c++0x
CFLAGS		:=-fPIC -c -Wall -O3 -D_ZET_RELEASE $(EXTRA_CFLAGS)
INCLUDES	:=-I. -I.. -I../.. -Isrc -I/usr/include/apr-1.0 $(EXTRA_INCLUDES)
LIBS			:=$(EXTRA_LIBS)
LDFLAGS		:=-lapr-1 -laprutil-1 $(EXTRA_LDFLAGS)

ifeq ($(LANG),cpp)
LDFLAGS		:=$(LDFLAGS) -lstdc++
endif

# ---------------
# APACHE2 OPTIONS
# ---------------

APACHE_LIBEXECDIR=`apxs -q LIBEXECDIR`
APACHE_SYSMODSDIR=`apxs -q SYSCONFDIR`/mods-available

# -------
# COMPILE
# -------

all: main

main: compile_all
	$(GCC) $(CFLAGS) $(INCLUDES) -o bin/$@.o $@.c
	$(GCC) $(CFLAGS) $(INCLUDES) -o bin/zet.o ../../zet.c
	gcc -shared -o bin/$(MODULE) bin/*.o $(LDFLAGS)
	@rm -rf bin/*.o

compile_all:
	@for dir in $(DIRS); do \
		for ext in $(EXTS); do \
			for file in $$dir/*$$ext; do \
				if [ -e $$file ]; then \
					if [ $$ext = ".cpp" ]; then \
						$(GPP) $(CFLAGS) $(INCLUDES) -o bin/$$(basename $$file).o $$file; \
					elif [ $$ext = ".c" ]; then \
						$(GCC) $(CFLAGS) $(INCLUDES) -o bin/$$(basename $$file).o $$file; \
					fi \
				fi \
			done \
		done \
	done

# -------
# INSTALL
# -------

install: mod-install
	service apache2 restart

uninstall: mod-uninstall
	service apache2 restart

mod-install:
	cp bin/$(MODULE) $(APACHE_LIBEXECDIR)/$(MODULE)
	chmod 644 $(APACHE_LIBEXECDIR)/$(MODULE)
	@echo "<Location /$(HANDLE)>" > $(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "SetHandler $(HANDLE)" >> $(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "</Location>" >> $(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "LoadModule $(NAME)_module $(APACHE_LIBEXECDIR)/$(MODULE)" > \
		$(APACHE_SYSMODSDIR)/$(NAME).load
	a2enmod $(NAME)

mod-uninstall:
	a2dismod $(NAME)
	rm -rf $(APACHE_LIBEXECDIR)/$(MODULE) $(APACHE_SYSMODSDIR)/$(NAME).*

# ----
# TEST
# ----

test: test-client

test-client:
	curl -i -X GET -H "X-Zet-Auth: HMAC-HS256" "http://client.local/$(HANDLE)"

test-server:
	curl -i -X GET -H "X-Zet-Auth: HMAC-HS256" "http://server.local/$(HANDLE)"

dep:
	@echo
	@readelf -d $(MODULE) | grep 'NEEDED'
	@echo

# --------------
# DEBIAN PACKAGE
# --------------

dist:
	mkdir -p /tmp/$(NAME)/DEBIAN
	mkdir -p /tmp/$(NAME)$(APACHE_LIBEXECDIR)
	mkdir -p /tmp/$(NAME)$(APACHE_SYSMODSDIR)
	cp -r $(MODULE) /tmp/$(NAME)$(APACHE_LIBEXECDIR)/$(MODULE)
	@echo "<Location /$(HANDLE)>" > /tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "SetHandler $(HANDLE)" >> /tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "</Location>" >> /tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).conf
	@echo "LoadModule $(NAME)_module $(APACHE_LIBEXECDIR)/$(MODULE)" > \
		/tmp/$(NAME)$(APACHE_SYSMODSDIR)/$(NAME).load
	cp -r deb-control /tmp/$(NAME)/DEBIAN/control
	cp -r deb-postinst /tmp/$(NAME)/DEBIAN/postinst
	cp -r deb-prerm /tmp/$(NAME)/DEBIAN/prerm
	chmod 755 /tmp/$(NAME)/DEBIAN/postinst
	chmod 755 /tmp/$(NAME)/DEBIAN/prerm
	dpkg-deb --build /tmp/$(NAME) $(NAME)-$(VERS)_amd64.deb
	rm -rf /tmp/$(NAME)

dist-install: dist
	apt-get install -y ./$(NAME)-$(VERS)_amd64.deb
	a2enmod $(NAME)

dist-uninstall:
	a2dismod $(NAME)
	apt-get purge -y $(NAME)
	apt-get autoremove -y

clean:
	rm -rf bin/*

.PHONY: compile_all install uninstall mod-install mod-uninstall \
				dist-install dist-uninstall host test test-client test-server dist dep \
				clean
