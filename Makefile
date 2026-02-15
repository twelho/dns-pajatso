-include config.mk

TZ ?= $(shell realpath /etc/localtime | sed 's|.*/zoneinfo/||')

.PHONY: shell
shell:
	docker build --build-arg TZ="$(TZ)" -t dns-pajatso .
	docker run -it --rm --name dns-pajatso -v .:/work:z -w /work --device /dev/kvm dns-pajatso

.PHONY: exec
exec:
	docker exec -it dns-pajatso bash -l

GO_SRC = $(filter-out %_test.go,$(wildcard *.go)) go.mod go.sum

dns-pajatso: $(GO_SRC)
	go build -o dns-pajatso .

.PHONY: test
test:
	go test ./...

GOK = $(CURDIR)/bin/gok
GOKRAZY_PARENT_DIR = $(CURDIR)/gokrazy
export GOKRAZY_PARENT_DIR

$(GOK):
	GOBIN=$(CURDIR)/bin go install github.com/gokrazy/tools/cmd/gok@latest

# NoPassword restricts the built-in gokrazy HTTP interface to localhost only. Reference:
# https://github.com/gokrazy/internal/blob/00a332bd5e47122e58c6fbd8b86082ad3572f6cc/config/config.go#L53-L63
define GOKRAZY_CONFIG
{
  "Hostname": "kasino",
  "Update": {
    "NoPassword": true
  },
  "KernelPackage": "github.com/rtr7/kernel",
  "FirmwarePackage": "github.com/rtr7/kernel",
  "SerialConsole": "ttyS0",
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
  "GokrazyPackages": [
    "github.com/gokrazy/gokrazy/cmd/dhcp",
    "github.com/gokrazy/gokrazy/cmd/ntp"
  ],
  "Environment": [
    "GOOS=linux",
    "GOARCH=amd64"
  ]
}
endef
export GOKRAZY_CONFIG

.PHONY: .check-config
.check-config:
	@test -n "$(zone)" || (echo "error: zone not set in config.mk" && exit 1)
	@test -n "$(tsig_name)" || (echo "error: tsig_name not set in config.mk" && exit 1)
	@test -n "$(tsig_secret)" || (echo "error: tsig_secret not set in config.mk" && exit 1)

.PHONY: .gokrazy-config
.gokrazy-config: $(GOK) .check-config
	mkdir -p $(GOKRAZY_PARENT_DIR)/kasino
	printf '%s' "$$GOKRAZY_CONFIG" > $(GOKRAZY_PARENT_DIR)/kasino/config.json
	$(GOK) -i kasino add $(CURDIR)

.PHONY: image
image: .gokrazy-config
	$(GOK) -i kasino overwrite --full /tmp/kasino.img --target_storage_bytes 1258299392 # 1.2 GiB
	qemu-img convert -f raw -O qcow2 /tmp/kasino.img kasino.qcow2
	rm -f /tmp/kasino.img
	@echo "built kasino.qcow2"

.PHONY: run
run: .gokrazy-config
	$(GOK) -i kasino vm run --graphic=false --netdev 'user,id=net0,hostfwd=udp::53-:53'

.PHONY: integration-test
integration-test: .check-config
	@echo "==> nsupdate: add TXT record"
	printf 'server 127.0.0.1\nzone $(zone)\nupdate add _acme-challenge.$(zone) 60 TXT "test-token"\nsend\n' | \
		nsupdate -y 'hmac-sha512:$(tsig_name):$(tsig_secret)'
	@echo "==> dig: verify TXT record"
	dig @127.0.0.1 _acme-challenge.$(zone) TXT +short | tee /dev/stderr | grep -q '"test-token"'
	@echo "==> nsupdate: delete TXT record"
	printf 'server 127.0.0.1\nzone $(zone)\nupdate delete _acme-challenge.$(zone) TXT\nsend\n' | \
		nsupdate -y 'hmac-sha512:$(tsig_name):$(tsig_secret)'
	@echo "==> dig: verify deletion"
	@test -z "$$(dig @127.0.0.1 _acme-challenge.$(zone) TXT +short)"
	@echo "==> all integration tests passed"

.PHONY: keygen
keygen:
	dd if=/dev/urandom bs=64 count=1 2>/dev/null | base64 -w0
	@echo

.PHONY: clean
clean:
	rm -rf dns-pajatso bin/ gokrazy/ kasino.qcow2
