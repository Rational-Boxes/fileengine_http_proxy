# FileEngine HTTP Bridge — packaging Makefile
#
# Mirrors the file_engine_core packaging flow: `dist` builds a source tarball
# from the committed HEAD (so packages always reflect committed code), and the
# rpm-package / deb-package targets feed that tarball to rpmbuild / dpkg.

.PHONY: dist rpm-package deb-package clean

VERSION := 1.0.0
PACKAGE_NAME := fileengine-http-bridge
BUILD_DIR := build-pkg

# Create distribution tarball. The --prefix matches the dir name the RPM spec's
# %setup -n expects and that dpkg-buildpackage unpacks into.
dist:
	@echo "Creating distribution tarball..."
	@git archive --format=tar.gz \
	    --prefix=$(PACKAGE_NAME)-$(VERSION)/ \
	    --output=$(PACKAGE_NAME)-$(VERSION).tar.gz HEAD

# Build RPM package
rpm-package: dist
	@echo "Building RPM package..."
	@mkdir -p $(HOME)/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SRPMS,SPECS}
	@cp $(PACKAGE_NAME)-$(VERSION).tar.gz $(HOME)/rpmbuild/SOURCES/
	@cp $(PACKAGE_NAME).spec $(HOME)/rpmbuild/SPECS/
	@rpmbuild -bb $(HOME)/rpmbuild/SPECS/$(PACKAGE_NAME).spec

# Build Debian package (debian/ ships inside the tarball)
deb-package: dist
	@echo "Building Debian package..."
	@mkdir -p $(BUILD_DIR)
	@cp $(PACKAGE_NAME)-$(VERSION).tar.gz $(BUILD_DIR)/
	@cd $(BUILD_DIR) && tar -xzf $(PACKAGE_NAME)-$(VERSION).tar.gz
	@cd $(BUILD_DIR)/$(PACKAGE_NAME)-$(VERSION) && dpkg-buildpackage -us -uc -b

clean:
	@echo "Cleaning packaging artifacts..."
	@rm -rf $(BUILD_DIR)
	@rm -f *.tar.gz *.deb *.rpm
