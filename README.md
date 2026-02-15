# dns-pajatso

`dns-pajatso` is a workaround enabling ACME DNS-01 challenges to be issued from network connections with incoming port 53 firewalled. Essentially, this is a simple external DNS server that can host the `_acme-challenge` TXT record and permit updates to it through RFC 2136. To be hostable externally, the server is packaged as a [gokrazy appliance](https://gokrazy.org/), which is baked into an x86_64 VM disk image to be runnable on a cloud provider. It is stateless and needs minimal resources, intended to be run on the free tiers offered by cloud providers.

## Details

`dns-pajatso` is implemented as a simple Go CLI application, which can run standalone for testing purposes, such as through the `nsupdate` tool. The supported RFC 2136 options are intentionally limited: `dns-pajatso` will only accept updates to the `_acme-challenge` TXT record through HMAC-SHA512 TSIG. The record will also automatically expire and be deleted after 10 minutes. Explicit delete requests are also supported and do not fail if the record does not exist. Run `make pajatso` to build the binary.

For deployment as a VM, this repo contains the necessary tooling to build the gokrazy appliance VM image. Run `make automaatti tsig=<tsig_key>` to build the QCOW2 image, then upload it to your cloud provider. Choose the minimal x86_64 instance type available.
