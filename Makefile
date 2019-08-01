
ifeq ($(origin PYENV_ROOT), undefined)
$(error `pyenv` is required for the Target.)
endif

PYVER := $(lastword $(shell python --version 2>&1))
APPVER := $(strip $(shell cat version))
GITBRANCH := $(strip $(shell git rev-parse --abbrev-ref HEAD))
GITCOMMIT := $(strip $(shell git rev-parse --short HEAD))

all: build

rpm: build
	mkdir -p drms_toggle-$(APPVER)/bin drms_toggle-$(APPVER)/etc drms_toggle-$(APPVER)/etc/init.d
	cp dist/drms_toggle drms_toggle-$(APPVER)/bin
	cp drms_toggle.py drms_toggle-$(APPVER)
	cp -r etc drms_toggle-$(APPVER)
	cp build/pyinst-drms/base_library.zip drms_toggle-$(APPVER)/etc
	tar cvzf ~/rpmbuild/SOURCES/drms_toggle-$(APPVER).tar.gz drms_toggle-$(APPVER)
	rpmbuild -bb --define "DRMSVER $(APPVER)" --define "GITBRANCH $(GITBRANCH)" --define "GITCOMMIT $(GITCOMMIT)" drms.spec
	rm -rf drms_toggle-$(APPVER)

TGT=drms_toggle
rpmclean:	
	rm -rf build dist
	rm -rf drms_toggle-$(APPVER)
	rm -rf __pycache__
	cp -r ~/rpmbuild/RPMS/x86_64/$(TGT)*$(APPVER)* ./  
	rm -rf ~/rpmbuild/SOURCES/$(TGT)* \
	~/rpmbuild/BUILD/$(TGT)* \
	~/rpmbuild/RPMS/x86_64/$(TGT)* \
	~/rpmbuild/SPEC/$(TGT)* 

build: dist/drms_toggle

dist/drms_toggle: distclean
	env LD_LIBRARY_PATH=$(LD_LIBRARY_PATH):$(PYENV_ROOT)/versions/$(PYVER)/lib/ pyinstaller --onefile pyinst-drms.spec

.PHONY: distclean clean

distclean:
	rm -rf build dist
	rm -rf drms_toggle-$(APPVER)
	rm -rf __pycache__

clean:
	rm -rf build dist
	rm -rf drms_toggle-$(APPVER)
	rm -rf __pycache__
