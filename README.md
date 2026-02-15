# dns-pajatso

`dns-pajatso` is a workaround enabling ACME DNS-01 challenges to be issued from network connections with incoming port 53 firewalled. Essentially, this is a simple external DNS server that can host the `_acme-challenge` TXT record and permit updates to it through RFC 2136. To be hostable externally, the server is packaged as a [gokrazy appliance](https://gokrazy.org/), which is baked into an x86_64 VM disk image to be runnable on a cloud provider. It is stateless and needs minimal resources, intended to be run on the free tiers offered by cloud providers.

## Details

`dns-pajatso` is implemented as a simple standalone Go application. The supported RFC 2136 options are intentionally limited: `dns-pajatso` will only accept updates to the `_acme-challenge` TXT record through HMAC-SHA512 TSIG. The record will also automatically expire and be deleted after 10 minutes.

## Prerequisites

- (Rootless) Docker
- KVM support (if wanting to run the VM locally)
- A DNS zone delegated to the server's public IP

## Development environment

All build and test tooling (Go, QEMU, make, dig, nsupdate) is provided via a Docker container. Run `make` to build the image and drop into a shell:

```sh
make
```

To open an additional shell in the running container:

```sh
make exec
```

## Configuration

Create a `config.mk` file with your zone and TSIG credentials:

```makefile
zone = example.com.
tsig_name = acme-update.
tsig_secret = <base64-encoded HMAC-SHA512 key>
```

To generate a new TSIG secret:

```sh
make keygen
```

This outputs a random 64-byte key (matching SHA-512's block size), base64-encoded.

## Building

Build the standalone binary (inside the container):

```sh
make dns-pajatso
```

Build the gokrazy VM disk image:

```sh
make image
```

This produces `kasino.qcow2`, ready to upload to a cloud provider.

## Running the VM

Start the VM locally with QEMU (UDP port 53 forwarded to host/container):

```sh
make run
```

The VM boots gokrazy, which supervises `dns-pajatso` automatically. Logs are visible via `dmesg` on the serial console.

## Testing

Run unit tests:

```sh
make test
```

Run integration tests against the running VM (requires `make run` in another terminal):

```sh
make integration-test
```

The integration test uses `nsupdate` and `dig` to verify the full cycle: add a TXT record, query it, delete it, and confirm deletion.

## Supported operations

- **Query**: TXT lookups for `_acme-challenge.<zone>` (returns the current challenge token, if set)
- **Update (add)**: RFC 2136 update to set the `_acme-challenge` TXT record (TSIG required)
- **Update (delete)**: RFC 2136 update to remove the TXT record (TSIG required)

The record automatically expires after 10 minutes. Only `_acme-challenge` TXT records are accepted; all other update requests are refused.

## Make targets

| Target | Description |
|---|---|
| `shell` | Build container and open interactive shell (default) |
| `exec` | Open another shell in the running container |
| `dns-pajatso` | Build the standalone binary |
| `image` | Build the gokrazy VM disk image (`kasino.qcow2`) |
| `run` | Boot the VM locally with QEMU |
| `test` | Run unit tests |
| `integration-test` | Run integration tests against running VM |
| `keygen` | Generate a random TSIG secret |
| `clean` | Remove build artifacts |
