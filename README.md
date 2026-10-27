# nft-dns
Make the nftables resolve fqdn on-the-fly !

This is a fork of [azlux/nft-dns](https://git.azlux.fr/azlux/nft-dns). Its README follows [below](#readme-of-azluxnft-dns),
this section lists what has changed notably compared to it.

## Changes in this fork
- **No Pydantic**, so no recent Debian is required: runs with Python 3.9 to 3.14, and Python 3.9 with dnspython 2.0 (Debian 11) is enough except for `custom_resolver` (see the manual).
  azlux/nft-dns needs Debian 12 or later for Pydantic, or Python 3.12 or later with Pydantic 2.
- **Shared addresses**: an address that several domains resolve to stays in the set as long as one of them still resolves to it.
- **Missing records**: domains that do not exist or have no A/AAAA record are checked again after `max_ttl`, instead of being disabled for good or terminating the program.
- **Resolver failures** such as timeouts or SERVFAIL no longer terminate the program; the known addresses are kept and the lookup is retried.
- **Timing**: an entry is resolved again `update_delay` after its TTL, with sub-second precision. The original calculation slept for almost a day when an update took longer than the next TTL.
- **Grace period**: with `removal_grace`, addresses that are no longer resolved stay in the set for a while, for clients that resolved them shortly before.
- **Restarts**: with `clear_on_exit = False`, the addresses stay in the sets on exit and are taken over on the next start instead of flushing the sets.
- **Cleanup on exit** removes only the addresses added by nft-dns instead of flushing the sets.
- **Round Robin DNS**: with `rr_dns` and `rr_tries`, a domain is resolved several times per update.

The options are described in the [manual](./MANUAL.md). The APT packages mentioned below are built from azlux/nft-dns and do not contain these changes.

-----
# README of azlux/nft-dns
Unchanged except for the requirements, which apply to this fork.

The source of this project is https://git.azlux.fr/azlux/nft-dns.

Back on iptables, fqdn was available into rules, but was resolved at start only. This have never been improved.

This project try to resolve this limitation.
NFT-DNS start with it own configuration file, will resolve the DNS and keep the TTL, then will populate the NFT [named SET](https://wiki.nftables.org/wiki-nftables/index.php/Sets#Named_sets_specifications).

The script will make DNS query each time the TTL reach zero, this way, your system will resolve an entries already accepted (or refused) by your firewall, even if the domain have changed its IP.
The script is both IPv4 and IPv6 compatible.

-----
## Quick Start Guide
1. [Features](#features)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Help](#help)
5. [TODO](#todo)

## Features
- FQDN support
   - *wildcard only if there are a Wildcard DNS record 
- Configuration via simple config files into a folder (allow multiple config file)
  - Config with .ini format 
- Packaged with apt
  - upgrade with APT 
  - Service packaged with systemd

## Requirements
To use this program you need:
- At least **Python 3.9**
- A NFTABLES with an **already prepared** [named SET](https://wiki.nftables.org/wiki-nftables/index.php/Sets#Named_sets_specifications) (or more).
  - the named sets used here **NEED** to be **EXCLUSIVE** to nft-dns.
  - If the set doesn't exist, the program will stop itself.
  - For testing, you can have sets you don't call into any rules.
- If your OS have systemd, the package will prepare the systemd service too.

## Installation
### With APT (recommended)
```bash
    echo "deb [signed-by=/usr/share/keyrings/azlux-archive-keyring.gpg] http://packages.azlux.fr/debian/ trixie main" | sudo tee /etc/apt/sources.list.d/azlux.list
    sudo wget -O /usr/share/keyrings/azlux-archive-keyring.gpg  https://azlux.fr/repo.gpg
    sudo apt update
    sudo apt install nft-dns
    # Here you change the config
    # Then you can start and enable the service
    sudo systemctl enable nft-dns
    sudo systemctl start nft-dns
```

### Manually
You can just clone the project, the start script is `nft-dns.py`. But you will have not auto-update.
You will need to create your one init service.
You also need to install the dependencies with pip3 or debian packages.

## Configuration
You can write your own config file with [the manual](./MANUAL.md) (available also with `man nft-dns`)

Read the manual for explanation of configs entries.

You can also copy the `/etc/nft-dns.conf` file as a example, and uncomment values (`cp /etc/nft-dns.conf /etc/nft-dns.d/cutsom.conf`).

## Help
### Command line
Use `nft-dns.py --help` to get the usage help.

### Man page
Use `man nft-dns` to get the config help

## TODO
1. pcap capture (as option) to support true wildcard
