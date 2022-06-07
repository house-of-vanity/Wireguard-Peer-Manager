#!/usr/bin/env python3
# Author: 'UltraDesu <ab@hexor.ru>'
# Home: https://github.com/house-of-vanity/Wireguard-Peer-Manager

import wgconfig # default iniparser cannot read WG configs.
import logging
import json as _json
import ipaddress
import argparse
import configparser
from typing import TypedDict
from subprocess import call, Popen, PIPE
from socket import getfqdn
from os import path, mkdir
from base64 import b64encode, b64decode
from nacl.public import PrivateKey
from ipaddress import ip_address
from datetime import date

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger('generator')

# Create the parser
my_parser = argparse.ArgumentParser()

# Add the arguments
args = {
    "--update": {
        "action": "store_true",
        "default": False,
        "desc": "Regenerate all client configs"
    },
    "--json": {
        "action": "store_true",
        "default": False,
        "desc": "Print all Wireguard statistics in JSON"
    },
    "--peer": {
        "action": "store",
        "default": None,
        "desc": "Add new peer"
    },
    "--delete": {
        "action": "store",
        "default": None,
        "desc": "Delete peer"
    },
    "--config": {
        "action": "store",
        "default": "wg0",
        "desc": "Config to use, default wg0"
    },
}
for arg in args.items():
    my_parser.add_argument(arg[0], action=arg[1]['action'], default=arg[1]['default'])

help_msg = ""
for arg in args.items():
    help_msg += f"  {arg[0]}\t{arg[1]['desc']}\n"

## Reading config
# Execute the parse_args() method
args = my_parser.parse_args()
peer_name = args.peer
del_name = args.delete
is_update = args.update
json = args.json
wpm_config = configparser.ConfigParser()
client_dir = f"/etc/wireguard/clients_{args.config}"
if not path.isdir(client_dir):
    log.info("Creating clients directory %s", client_dir)
    mkdir(client_dir)
if wpm_config.read('wpm.conf'):
    ips = wpm_config['Interface'].get('allowed_ips', '0.0.0.0/0')
    dns = wpm_config['Interface'].get('dns', '8.8.8.8')
    hostname = wpm_config['Interface'].get('hostname', getfqdn())
    config = args.config if args.config else (wpm_config['Interface'].get('config', 'wg0'))
else:
    ips = '0.0.0.0/0'
    dns = '8.8.8.8'
    hostname = getfqdn()
    config = args.config
log.debug('Using %s WG config file.', config)


class WG_peer(TypedDict):
    preshared_key: str
    endpoint: str
    latest_handshake: int
    transfer_rx: int
    transfer_tx: int
    persistent_keepalive: bool
    allowed_ips: list


class Interface(TypedDict):
    name: str
    private_key: str
    public_key: str
    listen_port: int
    fwmark: str
    peers: list
    started: str


class Wireguard(TypedDict):
    interfaces: dict


wg_state = Wireguard({})


def wg_json():
    cmd = ["/usr/bin/wg", "show", "all", "dump"]
    proc = Popen(cmd,
                            stdout=PIPE,
                            stderr=PIPE,
                            universal_newlines=True
                            )
    stdout, stderr = proc.communicate()

    for v in stdout.split('\n'):
        cmd = ["systemctl", "show", "wg-quick@wg0", "--property", "InactiveEnterTimestamp"]
        proc = Popen(cmd,
                            stdout=PIPE,
                            stderr=PIPE,
                            universal_newlines=True
                            )
        stdout, stderr = proc.communicate()
        args = v.split('\t')
        if len(args) == 5:
            interface = Interface(
                name=args[0],
                private_key=args[1],
                public_key=args[2],
                listen_port=args[3],
                fwmark=args[4],
                started=stdout.strip().split("=")[1],
                peers=[])
            wg_state[interface['name']] = interface
        elif len(args) == 9:
            allowed_ips = args[4].replace(' ', '').split(',')
            peer = WG_peer(
                preshared_key=args[1],
                endpoint=args[3],
                latest_handshake=int(args[5]),
                transfer_rx=int(args[6]),
                transfer_tx=int(args[7]),
                persistent_keepalive=args[8],
                allowed_ips=allowed_ips)
            wg_state[args[0]]['peers'].append(peer)
        else:
            pass
    #return _json.dumps(wg_state)
    return wg_state

class Peer:
    def __init__(self, peer=None, allowed_ips=None, comment='None'):
        self.comment = comment
        self.managed = False
        if peer:
            self.pub_key = peer['PublicKey']
            self.allowed_ips = peer['AllowedIPs']
            try:
                data = list(map(str.strip, peer['_rawdata'][0].replace('#', '').split(';')))
                if len(data) != 2:
                    self.priv_key = self.generate_key()
                    self.pub_key = self.public_key(self.priv_key)
                else:
                    self.priv_key = data[0].split(':')[1].strip()
                    self.comment = data[1].split(':')[1].strip()
            except:
                pass
        else:
            self.priv_key = self.generate_key()
            self.pub_key = self.public_key(self.priv_key)
            self.allowed_ips = allowed_ips if allowed_ips else Helper(cfg_path=config).next_ip

        self.full_comment = "# priv_key: " + " ; ".join([self.priv_key, "comment: " + comment])



    def generate_key(self):
        """Generates a new private key"""
        private = PrivateKey.generate()
        return b64encode(bytes(private)).decode("ascii")


    def public_key(self, private_key):
        """Given a private key, returns the corresponding public key"""
        private = PrivateKey(b64decode(private_key))
        return b64encode(bytes(private.public_key)).decode("ascii")

    def gen_config(self, helper):
        """Generate peer config"""
        filename = f"{client_dir}/{self.comment.replace(' ', '_')}"
        _wg = wgconfig.WGConfig(f"{filename}.conf")
        _wg.initialize_file() 
        _wg.add_attr(None, 'Address', self.allowed_ips)
        _wg.add_attr(None, 'DNS', helper.dns)
        _wg.add_attr(None, 'PrivateKey', self.priv_key)
        _wg.add_peer(helper.server_pub_key)
        _wg.add_attr(helper.server_pub_key, 'AllowedIPs', f'{helper.dns}/32, {ips}')
        _wg.add_attr(helper.server_pub_key, 'Endpoint', f"{helper.server_addr}")
        _wg.add_attr(helper.server_pub_key, 'PersistentKeepalive', 10)
        _wg.write_file()
        call(f'qrencode -r {filename}.conf -o {filename}-qr.png', shell=True)
        call(f'qrencode -t ansiutf8 -r {filename}.conf -o {filename}-qr.txt', shell=True)
        log.info(f"Updated config for {filename}")


class Helper:
    def __init__(
            self,
            cfg_path):
        self.cfg_path = cfg_path
        self.server_addr = hostname
        self.dns = dns
        self.wg = wgconfig.WGConfig(cfg_path)
        self.wg.read_file()

    @property
    def server_pub_key(self):
        """Return server public key"""
        return Peer().public_key(self.wg.interface['PrivateKey'])

    @property
    def peer_list(self):
        """Return list of WG peers"""
        peer_list = list()
        for i, v in self.wg.peers.items():
            peer_list.append(Peer(peer=v))
        return peer_list

    @property
    def ip_list(self):
        """Return list of IPs"""
        ip_list = list()
        ip_list.append(ipaddress.ip_address(Helper(cfg_path=config).wg.interface['Address'].split('/')[0]))
        for i, v in self.wg.peers.items():
            try:
                ip_raw = v.get('AllowedIPs', None)
                if isinstance(ip_raw, str):
                    ip = ipaddress.ip_address(ip_raw.split('/')[0])
                elif isinstance(ip_raw, list):
                    ip = ipaddress.ip_address(ip_raw[0].split('/')[0])
                ip_list.append(ip)
            except:
                pass
        ip_list.sort()
        return ip_list

    @property
    def next_ip(self):
        """Return next free IP"""
        return self.ip_list[-1]+1


    def add_peer(self, comment):
        """Generate a new peer"""
        cl = Peer(comment=comment)
        self.wg.add_peer(cl.pub_key, cl.full_comment)
        self.wg.add_attr(cl.pub_key, 'AllowedIPs', f"{self.ip_list[-1]+1}/32")
        cl.gen_config(self)

    def del_peer(self, name):
        """Delete given peer"""
        try:
            pub_key = list(filter(lambda peer: peer['name'] == name, list_peers()))[0]['pub_key']
        except:
            log.info("Couldn't find peer.")
            return False
        self.wg.del_peer(pub_key)
        filename = f"{client_dir}/{name.replace(' ', '_')}"
        call(f"rm -f {filename}*", shell=True)

def add_peer(peer_name):
    log.info('Generate a new peer config.')
    helper = Helper(cfg_path=config)
    helper.add_peer(peer_name)
    helper.wg.write_file()
    call("bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'",shell=True)

def del_peer(peer_name):
    log.info(f'Remove given peer {peer_name}.')
    helper = Helper(cfg_path=config)
    helper.del_peer(peer_name)
    helper.wg.write_file()
    call("bash -c 'wg syncconf wg0 <(wg-quick strip wg0)'",shell=True)

def update_configs():
    log.info("Update all clients configs.")
    for peer in Helper(cfg_path=config).peer_list:
        peer.gen_config(Helper(cfg_path=config))

def list_peers():
    return [{'name': p.comment, 'ip': p.allowed_ips, 'pub_key': p.pub_key} for p in Helper(cfg_path=config).peer_list]


if __name__ == '__main__':
    if del_name:
        del_peer(del_name)
    elif not is_update and peer_name:
        add_peer(peer_name)
    elif is_update:
        update_configs()
    elif json:
    	#print(_json.dumps(wg_json()))
    	print(wg_json()['wg0']['peers'][0])
    else:
        print(help_msg)
