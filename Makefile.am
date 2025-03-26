# against of error: Makefile.am:3: `doc_DATA' is used but `docdir' is undefined
docdir = @docdir@

SUBDIRS = src

man_MANS= doc/netdiscover.8

EXTRA_DIST = \
	autogen.sh \
	doc/create-man.sh \
	doc/netdiscover.8 \
	doc/netdiscover.txt \
	README.md \
	README.rpm \
	rpm/mandriva.spec \
	rpm/redhat.spec \
	update-oui-database.sh

distclean-local:
	-rm -rf autom4te.cache/ \
	build-aux/

	rm -f \
	aclocal.m4 \
	config.h.in \
	configure \
	doc/Makefile.in \
	INSTALL \
	Makefile.in \
	src/Makefile.in
