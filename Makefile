-include config.mk

.PHONY: pajatso automaatti clean

pajatso:
	go build -o dns-pajatso .

GOKRAZY_DIR = $(HOME)/gokrazy/automaatti

automaatti: pajatso
	@test -n "$(zone)" || (echo "error: zone not set in config.mk" && exit 1)
	@test -n "$(tsig_name)" || (echo "error: tsig_name not set in config.mk" && exit 1)
	@test -n "$(tsig_secret)" || (echo "error: tsig_secret not set in config.mk" && exit 1)
	mkdir -p $(GOKRAZY_DIR)
	printf '{\n  "Hostname": "automaatti",\n  "Packages": [\n    "github.com/twelho/dns-pajatso"\n  ],\n  "PackageConfig": {\n    "github.com/twelho/dns-pajatso": {\n      "CommandLineFlags": [\n        "--zone=$(zone)",\n        "--tsig-name=$(tsig_name)",\n        "--tsig-secret=$(tsig_secret)"\n      ]\n    }\n  }\n}\n' > $(GOKRAZY_DIR)/config.json
	gok -i automaatti overwrite --full /tmp/automaatti.img
	qemu-img convert -f raw -O qcow2 /tmp/automaatti.img automaatti.qcow2
	rm -f /tmp/automaatti.img
	@echo "Built automaatti.qcow2"

clean:
	rm -f dns-pajatso automaatti.qcow2
