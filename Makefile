.PHONY: lint test build-ova clean install

VERSION := $(shell cat VERSION)
PROJECT := codered-sensor

lint:
	shellcheck build/*.sh build/packer/scripts/*.sh
	python3 -m pylint firstboot/ shell/ --disable=C0114,C0115,C0116
	yamllint salt/

test:
	python3 -m pytest tests/ firstboot/tests/ shell/tests/ -v

build-ova:
	cd build/packer && packer init . && packer build -var "version=$(VERSION)" sensor.pkr.hcl

build-ova-manual:
	bash build/build-ova.sh $(VERSION)

install:
	@echo "Installing CodeRed Sensor overlay..."
	install -d /opt/codered/{firstboot,shell}
	install -d /etc/codered
	install -m 0755 firstboot/*.py /opt/codered/firstboot/
	install -m 0755 shell/*.py /opt/codered/shell/
	install -m 0644 conf/codered.defaults /etc/codered/codered.defaults
	install -m 0644 firstboot/firstboot.service /etc/systemd/system/codered-firstboot.service
	cp -r salt/pillar/codered /opt/so/saltstack/local/pillar/
	cp -r salt/states/codered /opt/so/saltstack/local/salt/
	systemctl daemon-reload
	systemctl enable codered-firstboot.service
	@echo "Install complete. Reboot to start first-boot wizard."

clean:
	rm -rf build/output-*
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name '*.pyc' -delete 2>/dev/null || true
