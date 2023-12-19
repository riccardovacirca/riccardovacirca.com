# ------------------------------------------------------------------------------
#
# mod_z_session.c
# ZET session example module
#
# Copyright (c)2023 Riccardo Vacirca <rvacirca23@gmail.com>
#
# ------------------------------------------------------------------------------

NAME := session
DESC := ZET session module
VERS := 0.0.1
LANG := c
DIRS := src
EXTS := .c
MANT := Riccardo Vacirca<rvacirca23@gmail.com>
HOME := http://riccardovacirca.com
ARCH := amd64
DEPS := libapr1 (>= 1.6.5), libaprutil1 (>= 1.6.1), libc6 (>= 2.31-13)

# ------------------------------------------------------------------------------

GIT_MAIL := "rvacirca23@gmail.com"
GIT_USER := "riccardovacirca"

# ------------------------------------------------------------------------------

HANDLE	    := $(NAME)
MOD_NAME    := z_$(NAME)
MODULE_FILE	:= mod_$(MOD_NAME).so
PACKAGE     := libapache2-mod-z-$(NAME)
DIST_FILE   := $(PACKAGE)-$(VERS)_$(ARCH).deb

# ------------------------------------------------------------------------------
# COMPILER OPTIONS
# ------------------------------------------------------------------------------

EXTRA_CFLAGS		:=-D_ZET_HAS_APACHE -D_ZET_HAS_SESSION
EXTRA_INCLUDES	:=-I/usr/include/apache2
EXTRA_LIBS			:=
EXTRA_LDFLAGS		:=

# ------------------------------------------------------------------------------
# COMPILER GENERAL OPTIONS
# ------------------------------------------------------------------------------

GCC				:=gcc -std=gnu99
GPP				:=g++ -std=c++0x
CFLAGS		:=-fPIC -c -Wall -O3 -D_ZET_RELEASE $(EXTRA_CFLAGS)
INCLUDES	:=-I. -I.. -I../.. -Isrc -I/usr/include/apr-1.0 $(EXTRA_INCLUDES)
LIBS			:=$(EXTRA_LIBS)
LDFLAGS		:=-lapr-1 -laprutil-1 $(EXTRA_LDFLAGS)

ifeq ($(LANG),cpp)
LDFLAGS		:=$(LDFLAGS) -lstdc++
endif

# ------------------------------------------------------------------------------
# APACHE2 OPTIONS
# ------------------------------------------------------------------------------

APACHE_LIBEXECDIR=`apxs -q LIBEXECDIR`
APACHE_SYSMODSDIR=`apxs -q SYSCONFDIR`/mods-available

# ------------------------------------------------------------------------------
# COMPILE
# ------------------------------------------------------------------------------

all: $(MODULE_FILE)

$(MODULE_FILE): compile_all
	$(GCC) $(CFLAGS) $(INCLUDES) -o bin/mod_$(MOD_NAME).o mod_$(MOD_NAME).c
	$(GCC) $(CFLAGS) $(INCLUDES) -o bin/zet.o ../../zet.c
	gcc -shared -o bin/$(MODULE_FILE) bin/*.o $(LDFLAGS)
	@rm -rf bin/*.o

compile_all: clean
	@mkdir -p bin
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

# ------------------------------------------------------------------------------
# INSTALL
# ------------------------------------------------------------------------------

install: mod-disable-all mod-install
	a2enmod session
	a2enmod session_cookie
	service apache2 restart

uninstall: mod-disable-all mod-uninstall
	service apache2 restart

mod-install:
	cp bin/$(MODULE_FILE) $(APACHE_LIBEXECDIR)/$(MODULE_FILE)
	chmod 644 $(APACHE_LIBEXECDIR)/$(MODULE_FILE)
	@echo "<Location /$(HANDLE)>" > $(APACHE_SYSMODSDIR)/$(MOD_NAME).conf
	@echo "SetHandler $(HANDLE)" >> $(APACHE_SYSMODSDIR)/$(MOD_NAME).conf
	@echo "</Location>" >> $(APACHE_SYSMODSDIR)/$(MOD_NAME).conf
	@echo "LoadModule $(MOD_NAME)_module $(APACHE_LIBEXECDIR)/$(MODULE_FILE)" > \
		$(APACHE_SYSMODSDIR)/$(MOD_NAME).load
	a2enmod $(MOD_NAME)

mod-uninstall:
	rm -rf $(APACHE_LIBEXECDIR)/$(MODULE_FILE) \
				 $(APACHE_SYSMODSDIR)/$(MOD_NAME).*

mod-disable-all:
	a2dismod z_* session_* session || true

# ------------------------------------------------------------------------------
# TEST
# ------------------------------------------------------------------------------

test: test-client

test-client:
	curl -X GET -i "http://client.local/$(HANDLE)"

test-server:
	curl -c /tmp/$(MOD_NAME)_cookie.txt -b /tmp/$(MOD_NAME)_cookie.txt -X GET \
		-i "http://server.local/$(HANDLE)"

# ------------------------------------------------------------------------------
# DEPENDENCIES
# ------------------------------------------------------------------------------

dep:
	@echo
	@readelf -d bin/$(MODULE_FILE) | grep 'NEEDED'
	@echo

# ------------------------------------------------------------------------------
# DEBIAN PACKAGE
# ------------------------------------------------------------------------------

dist: all dist-dir dist-control dist-postinst dist-prerm dist-apache-conf
	cp -r bin/$(MODULE_FILE) /tmp/$(MOD_NAME)$(APACHE_LIBEXECDIR)/$(MODULE_FILE)
	dpkg-deb --build /tmp/$(MOD_NAME) $(DIST_FILE)
	rm -rf /tmp/$(MOD_NAME)

dist-dir:
	mkdir -p /tmp/$(MOD_NAME)/DEBIAN
	mkdir -p /tmp/$(MOD_NAME)$(APACHE_LIBEXECDIR)
	mkdir -p /tmp/$(MOD_NAME)$(APACHE_SYSMODSDIR)

dist-control:
	@echo "Source: $(MOD_NAME)" > /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Section: devel" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Priority: optional" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Maintainer: $(MANT)" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Standards-Version: $(VERS)" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Build-Depends: debhelper (>= 7)" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Homepage: $(HOME)" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Package: $(PACKAGE)" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Version: $(VERS)" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Essential: no" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Architecture: amd64" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Depends: $(DEPS)" >> /tmp/$(MOD_NAME)/DEBIAN/control
	@echo "Description: $(DESC)" >> /tmp/$(MOD_NAME)/DEBIAN/control

dist-postinst:
	@echo "#!/bin/bash" > /tmp/$(MOD_NAME)/DEBIAN/postinst
	@echo "chmod 644 $(APACHE_LIBEXECDIR)/$(MODULE_FILE)" \
		>> /tmp/$(MOD_NAME)/DEBIAN/postinst
	@echo "chmod 644 $(APACHE_SYSMODSDIR)/$(MOD_NAME).conf" \
		>> /tmp/$(MOD_NAME)/DEBIAN/postinst
	@echo "chmod 644 $(APACHE_SYSMODSDIR)/$(MOD_NAME).load" \
		>> /tmp/$(MOD_NAME)/DEBIAN/postinst
	@chmod 755 /tmp/$(MOD_NAME)/DEBIAN/postinst

dist-prerm:
	@echo "#!/bin/bash" > /tmp/$(MOD_NAME)/DEBIAN/prerm
	@chmod 755 /tmp/$(MOD_NAME)/DEBIAN/prerm

dist-apache-conf:
	@echo "<Location /$(HANDLE)>" > \
		/tmp/$(MOD_NAME)$(APACHE_SYSMODSDIR)/$(MOD_NAME).conf
	@echo "SetHandler $(HANDLE)" >> \
		/tmp/$(MOD_NAME)$(APACHE_SYSMODSDIR)/$(MOD_NAME).conf
	@echo "</Location>" >> \
		/tmp/$(MOD_NAME)$(APACHE_SYSMODSDIR)/$(MOD_NAME).conf
	@echo "LoadModule $(MOD_NAME)_module $(APACHE_LIBEXECDIR)/$(MODULE_FILE)" > \
		/tmp/$(MOD_NAME)$(APACHE_SYSMODSDIR)/$(MOD_NAME).load

dist-install:
	apt-get install -y ./$(DIST_FILE)
	a2enmod $(MOD_NAME)
	service apache2 restart

dist-uninstall:
	a2dismod $(MOD_NAME)
	apt-get purge -y $(PACKAGE)
	apt-get autoremove -y
	service apache2 restart

# ------------------------------------------------------------------------------
# GIT
# ------------------------------------------------------------------------------

push: clean-all
	@cd ../..
	git config user.email $(GIT_MAIL)
	git config user.name $(GIT_USER)
	git add .
	git commit -m "updated"
	git push origin main

# ------------------------------------------------------------------------------
# CLEAN
# ------------------------------------------------------------------------------

clean:
	@rm -rf bin

clean-all: clean
	@rm -rf *.deb /tmp/$(MOD_NAME) /tmp/$(MOD_NAME)_cookie.txt

.PHONY: $(MODULE_FILE) compile_all install uninstall mod-install mod-uninstall \
				dist-install dist-uninstall host test test-client test-server dist dep \
				clean
