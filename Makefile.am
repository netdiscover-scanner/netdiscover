# against of error: Makefile.am:3: `doc_DATA' is used but `docdir' is undefined
docdir = @docdir@

SUBDIRS = src doc

doc_DATA = \
        README\
        COPYING\
        AUTHORS\
        ChangeLog\
        NEWS\
        TODO

EXTRA_DIST = \
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
