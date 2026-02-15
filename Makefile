-include config.mk

.PHONY: all test automaatti clean

all: automaatti

GO_SRC = $(filter-out %_test.go,$(wildcard *.go)) go.mod go.sum

dns-pajatso: $(GO_SRC)
	go build -o dns-pajatso .

test:
	go test ./...

GOK = $(CURDIR)/bin/gok
GOKRAZY_PARENT_DIR = $(CURDIR)/gokrazy
export GOKRAZY_PARENT_DIR

$(GOK):
	GOBIN=$(CURDIR)/bin go install github.com/gokrazy/tools/cmd/gok@latest

define GOKRAZY_CONFIG
{
  "Hostname": "automaatti",
  "KernelPackage": "github.com/rtr7/kernel",
  "FirmwarePackage": "github.com/rtr7/kernel",
  "SerialConsole": "ttyS0,115200",
  "Packages": [
    "github.com/twelho/dns-pajatso"
  ],
  "PackageConfig": {
    "github.com/twelho/dns-pajatso": {
      "CommandLineFlags": [
        "--zone=$(zone)",
        "--tsig-name=$(tsig_name)",
        "--tsig-secret=$(tsig_secret)"
      ]
    }
  },
  "Environment": [
    "GOOS=linux",
    "GOARCH=amd64"
  ]
}
endef
export GOKRAZY_CONFIG

automaatti: $(GOK)
	@test -n "$(zone)" || (echo "error: zone not set in config.mk" && exit 1)
	@test -n "$(tsig_name)" || (echo "error: tsig_name not set in config.mk" && exit 1)
	@test -n "$(tsig_secret)" || (echo "error: tsig_secret not set in config.mk" && exit 1)
	mkdir -p $(GOKRAZY_PARENT_DIR)/automaatti
	printf '%s' "$$GOKRAZY_CONFIG" > $(GOKRAZY_PARENT_DIR)/automaatti/config.json
	$(GOK) -i automaatti add $(CURDIR)
	$(GOK) -i automaatti overwrite --full /tmp/automaatti.img --target_storage_bytes 1258299392 # 1.2 GiB
	qemu-img convert -f raw -O qcow2 /tmp/automaatti.img automaatti.qcow2
	rm -f /tmp/automaatti.img
	@echo "built automaatti.qcow2"

clean:
	rm -rf dns-pajatso bin/ gokrazy/ automaatti.qcow2
