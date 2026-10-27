#!/usr/bin/env python3
from __future__ import annotations

import argparse
import configparser
import json
import logging
import signal
import subprocess
from datetime import datetime, timedelta
from pathlib import Path
from threading import Event
from typing import Set

import dns.exception
import dns.resolver

import entry

config = configparser.ConfigParser(interpolation=None)

values = []
exit_event = Event()
logging.basicConfig(format='%(asctime)s %(levelname)s:%(message)s')
logging.getLogger().setLevel(logging.INFO)
clear_on_exit = True
last_seen = {}  # per set, last time the IP address was part of a valid DNS answer
next_removal = None  # when the next address that is no longer resolved runs out of removal_grace


def read_config():
    if args.config_file and Path(args.config_file).is_file():
        logging.info(f'Reading config file : {Path(args.config_file).absolute()}')
        config.read(Path(args.config_file))
    else:
        logging.error('Config file not found, Exiting...')
        exit(1)
    if config.has_option('GLOBAL', 'include_config_dir'):
        config_dir = Path(config['GLOBAL']['include_config_dir'])
        if not config_dir.is_dir():
            logging.error(f"Config directory is not a directory, Ignoring...")
        else:
            logging.info('Only config file with prefix .conf is read')
            logging.info(f"Reading config directory : {config_dir.absolute()}")
            list_config = list(config_dir.glob("*.conf"))
            [logging.info(f"   {i}") for i in list_config]
            config.read(list_config)

    global clear_on_exit
    clear_on_exit = config['GLOBAL'].getboolean('clear_on_exit', fallback=True)

    logging.info("# Parsing the configuration")
    if args.verbose or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('verbose')):
        logging.getLogger().setLevel(logging.DEBUG)

    global values
    for section in config.sections():
        if section != 'GLOBAL' and config[section].getboolean('enable', fallback=False):
            if config[section]["family"] in ['ip', 'ip6', 'inet']:
                family = config[section]["family"]
            else:
                print(f"Invalid configuration: family of section \"{section}\" must be one of ip, ip6 or inet")
                exit(1)
            table = config[section].get('table', fallback='filter')
            res = run_command(f"nft list set {family} {table} {config[section]['set_name']}")
            typeof = 4
            if not (args.dry_run or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('dry_run', fallback=False))):
                if "type ipv4_addr" in res:
                    typeof = 4
                    logging.debug(f"set {config[section]['set_name']} well defined in ipv4_addr family")
                elif "type ipv6_addr" in res:
                    typeof = 6
                    logging.debug(f"set {config[section]['set_name']} well defined in ipv6_addr family")
                else:
                    logging.error(f"Type of the {config[section]['set_name']} set not defined to \"ipv4_addr\" or \"ipv6_addr\" into the nftables set. Only theses type are allowed.")
                    exit(1)
            else:
                logging.info('The dry_run option force the typeof to "ipv4" since not command are executed to check that')
            for fqdn in config[section]["domains"].split(','):
                result = entry.ModelEntry(
                    set_name=config[section]["set_name"],
                    family=family,
                    table=table,
                    typeof=typeof,
                    fqdn=fqdn.strip(),
                    ip_list=[],
                    ttl=None,
                    rr_dns=config[section].getboolean('rr_dns', fallback=False),
                    next_update=None
                )
                values.append(result)
                logging.debug(result)
    if len(values) == 0:
        logging.error("No entries configurated, I've nothing to do, Exiting in tears...")
        exit(1)

    logging.info("# End of Parsing")


def update_dns() -> None:
    global values, next_removal
    if config.has_option('GLOBAL', 'custom_resolver'):
        res = dns.resolver.make_resolver_at(config['GLOBAL']['custom_resolver'])
    else:
        res = dns.resolver.Resolver()
    max_ttl = config['GLOBAL'].getint('max_ttl', fallback=86400)
    min_ttl = config['GLOBAL'].getint('min_ttl', fallback=300)
    rr_tries = config['GLOBAL'].getint('rr_tries', fallback=5)
    removal_grace = timedelta(seconds=config['GLOBAL'].getint('removal_grace', fallback=0))
    update_delay = config['GLOBAL'].getfloat('update_delay', fallback=2)
    error_retry_ttl = 30  # retry delay after a failed lookup (failure recheck timer of RFC 8767, section 5), still limited by min_ttl and max_ttl

    for i in values:
        if i.next_update and i.next_update > datetime.now():
            continue
        entry_old_ip_list = i.ip_list
        # the previous answer was valid until now, so removal_grace counts from here for addresses that are not resolved again
        seen = last_seen.setdefault(f"{i.family} {i.table} {i.set_name}", {})
        for ip in entry_old_ip_list:
            seen[ip] = datetime.now()
        logging.debug(f"Update for {i} in progress...")
        rd_type = "A"
        if i.typeof == 6:
            rd_type = "AAAA"

        try:
            i.ip_list = []
            for _ in range(0, rr_tries if i.rr_dns else 1):
                answer = res.resolve(i.fqdn, rdtype=rd_type)
                i.ip_list += [items.address for items in answer.rrset if items.address not in i.ip_list]
                i.ttl = answer.rrset.ttl

            i.ip_list.sort()

        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer) as e:
            logging.debug(f"Failed to get {rd_type} record for \"{i.fqdn}\", retrying again in {max_ttl} seconds. (Reason: {e})")
            i.ip_list = []
            i.ttl = max_ttl

        except dns.exception.DNSException as e:
            # resolver unreachable or failing (timeout, SERVFAIL, ...): this says nothing about the domain, so keep its addresses instead of exiting
            logging.warning(f"Failed to resolve {rd_type} record for \"{i.fqdn}\", keeping previous addresses and retrying later. (Reason: {e})")
            i.ip_list = entry_old_ip_list
            i.ttl = error_retry_ttl

        # Calculate next update for this entry
        ttl_adjusted = max(min(i.ttl, max_ttl), min_ttl)  # Value between min_ttl and max_ttl (inclusive)
        i.next_update = datetime.now() + timedelta(seconds=ttl_adjusted + update_delay)  # adding update_delay to make sure the cache really is cleared

        logging.debug(i)
        if entry_old_ip_list != i.ip_list:
            logging.info(f"Updating the IPv{i.typeof} addresses for {i.fqdn}. Previous: {entry_old_ip_list}; new: {i.ip_list}")
        else:
            logging.debug(f"The IPv{i.typeof} addresses for {i.fqdn} did not change")

    updated_ip_set = {}
    for i in values:
        set_specifier = f"{i.family} {i.table} {i.set_name}"
        updated_ip_set[set_specifier] = updated_ip_set.get(set_specifier, set()) | set(map(str, i.ip_list))

    # addresses no longer resolved stay in the set until they have not been seen for removal_grace,
    # so programs that resolved them shortly before can still connect
    now = datetime.now()
    not_seen_now = []
    for set_specifier, ips in updated_ip_set.items():
        seen = last_seen.setdefault(set_specifier, {})
        old_ips = set(seen)
        for ip in ips:
            seen[ip] = now
        for ip, seen_at in list(seen.items()):
            if ip in ips:
                continue
            if now - seen_at >= removal_grace:
                del seen[ip]
            else:
                not_seen_now.append(seen_at)
                logging.debug(f"Keeping {ip} in set {set_specifier} until {seen_at + removal_grace}, last seen {seen_at}")
        apply_config_entry(set_specifier, old_ips, set(seen))

    next_removal = min(not_seen_now) + removal_grace if not_seen_now else None


def get_next_run_timer() -> datetime:
    return min([date.next_update for date in values] + ([next_removal] if next_removal else []))


def apply_config_entry(set_specifier: str, old_ip_set: Set[str], updated_ip_set: Set[str]) -> None:
    added_ips = updated_ip_set - old_ip_set
    removed_ips = old_ip_set - updated_ip_set

    if added_ips:
        run_command(f"nft add element {set_specifier} {{{', '.join(added_ips)}}}")
        logging.info(f"Added {len(added_ips)} entries to set {set_specifier}")

    if removed_ips:
        run_command(f"nft delete element {set_specifier} {{{', '.join(removed_ips)}}}")
        logging.info(f"Removed {len(removed_ips)} entries from set {set_specifier}")

    if not added_ips and not removed_ips:
        logging.info(f"Set {set_specifier} did not change")


def read_existing_entries():
    # when not removing entries on exit, the sets still hold the addresses of the previous run: adopt them as seen at start
    # instead of flushing the sets, so an address only disappears once it was not confirmed for removal_grace
    start = datetime.now()
    for set_specifier in {f"{i.family} {i.table} {i.set_name}" for i in values}:
        res = run_command(f"nft -j list set {set_specifier}")
        if not res:
            continue
        seen = last_seen.setdefault(set_specifier, {})
        for item in json.loads(res)['nftables']:
            elements = item.get('set', {}).get('elem', [])
            for element in elements if isinstance(elements, list) else [elements]:
                # a plain address, or an elem object if the set has timeouts, counters or comments
                ip = element['elem'].get('val') if isinstance(element, dict) and 'elem' in element else element
                if isinstance(ip, str):
                    seen[ip] = start
                else:
                    logging.warning(f"Ignoring element {element} of set {set_specifier}, only single addresses are managed")
        logging.info(f"Found {len(seen)} existing entries in set {set_specifier}")


def remove_config_entries():
    logging.info("Cleaning all added entries")

    # clear sets, including addresses still kept for removal_grace
    for set_specifier, seen in last_seen.items():
        if seen:
            run_command(f"nft delete element {set_specifier} {{{', '.join(seen)}}}")


def run_command(cmd: str) -> str | None:
    logging.debug(f"Command to run : {cmd}")
    if not (args.dry_run or (config.has_option('GLOBAL', 'verbose') and config['GLOBAL'].getboolean('dry_run', fallback=False))):
        try:
            res = subprocess.run(cmd, capture_output=True, text=True, check=True, shell=True)
            return res.stdout
        except subprocess.CalledProcessError as e:
            logging.error(f"Command {cmd} failed with code {e.returncode}: {e}\n{e.stdout}\n{e.stderr}")
        except FileNotFoundError:
            logging.error("The nft command isn't found, Run with --dry-run to avoid nftable change tries")
            exit(1)
    else:
        logging.debug("Dry-run detected, logging only, the previous command isn't executed")
        return None


def run_loop():
    while not exit_event.is_set():
        update_dns()
        next_run = get_next_run_timer()
        # sleep at least 0.1s, so that a TTL of 0 with update_delay = 0 does not resolve in a loop without pause
        sleep_second = max((next_run - datetime.now()).total_seconds(), 0.1)  # using total_seconds() instead of seconds so seconds don't wrap around to almost a day if next_run already passed
        logging.info(f"Sleeping for {sleep_second:.1f}s")
        exit_event.wait(sleep_second)

    if clear_on_exit:
        # cleanup on exit
        remove_config_entries()


def main():
    read_config()
    if not clear_on_exit:
        read_existing_entries()
    run_loop()


def handler(signum, frame):
    logging.warning(f"{signal.Signals(signum).name}({signum}) signal received. Exiting")
    exit_event.set()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='DNS plugin for NFTables')
    parser.add_argument('-c', '--config', type=str, dest='config_file', default='/etc/nft-dns.conf', help='Config file')
    parser.add_argument('-t', '--dry-run', dest='dry_run', action="store_true", help="Test Mode, dry-run will not run any nftables command, usefull with verbose mode")
    parser.add_argument('-v', '--verbose', dest='verbose', action="store_true", help="Verbose logging mode, will log all actions")
    args = parser.parse_args()

    signal.signal(signal.SIGINT, handler)  # For simple CTRL+C
    signal.signal(signal.SIGTERM, handler)  # For Systemd stop
    main()
