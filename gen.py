#!/usr/bin/env python3
# Author: 'UltraDesu <ab@hexor.ru>'
# Home: https://github.com/house-of-vanity/Wireguard-Peer-Manager

import wgconfig # default iniparser cannot read WG configs.
import logging
import json
import ipaddress
import argparse
import configparser
from socket import getfqdn
from os import system
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
my_parser.add_argument('--update', action='store_true', default=False)
my_parser.add_argument('--peer', action='store', type=str)
my_parser.add_argument('--delete', action='store', type=str)
my_parser.add_argument('--config', action='store', default='wg0', type=str)

## Reading config
# Execute the parse_args() method
args = my_parser.parse_args()
peer_name = args.peer
del_name = args.delete
is_update = args.update
wpm_config = configparser.ConfigParser()
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
log.info('Using %s WG config file.', config)



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
        filename = f"clients/{self.comment.replace(' ', '_')}"
        _wg = wgconfig.WGConfig(f"{filename}.conf")
        _wg.initialize_file() 
        _wg.add_attr(None, 'Address', self.allowed_ips)
        _wg.add_attr(None, 'DNS', helper.dns)
        _wg.add_attr(None, 'PrivateKey', self.priv_key)
        _wg.add_peer(helper.server_pub_key)
        _wg.add_attr(helper.server_pub_key, 'AllowedIPs', f'{helper.dns}/32, {ips}')
        _wg.add_attr(helper.server_pub_key, 'Endpoint', f"{helper.server_addr}:51820")
        _wg.add_attr(helper.server_pub_key, 'PersistentKeepalive', 10)
        _wg.write_file()
        system(f'qrencode -r {filename}.conf -o {filename}-qr.png')
        system(f'qrencode -t ansiutf8 -r {filename}.conf -o {filename}-qr.txt')
        log.info(f"Updated config for {self.comment}")


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

def add_peer(peer_name):
    log.info('Generate a new peer config.')
    helper = Helper(cfg_path=config)
    helper.add_peer(peer_name)
    helper.wg.write_file()
    system(f'systemctl restart wg-quick@{config}.service')

def del_peer(peer_name):
    log.info(f'Remove given peer {peer_name}.')
    helper = Helper(cfg_path=config)
    helper.del_peer(peer_name)
    helper.wg.write_file()
    system(f'systemctl restart wg-quick@{config}.service')

def update_configs():
    log.info("Update all clients configs.")
    for peer in Helper(cfg_path=config).peer_list:
        peer.gen_config(Helper(cfg_path=config))

def list_peers():
    return [{'name': p.comment, 'ip': p.allowed_ips, 'pub_key': p.pub_key} for p in Helper(cfg_path=config).peer_list]


if __name__ == '__main__':
    if del_name:
        del_peer(del_name)

    if not is_update and peer_name:
        add_peer(peer_name)

    if is_update:
        update_configs()
