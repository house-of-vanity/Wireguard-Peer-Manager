# Wireguard-Peer-Manager
![image](https://user-images.githubusercontent.com/4666566/117325184-56f7f800-ae45-11eb-9003-b85aadbf5ff0.png)

Adds Wireguard peers to config, reload it and send client config back via Telegram. 

**FYI: That tool stores client private keys into server config as comments.**

How to use:

```shell


# create initial wg config or use your own.
# P.S. Keep in mind that WPM can't manage peers created my hands
# due to absence of client private key.
$ cd /etc/wireguard
$ git clone https://github.com/house-of-vanity/Wireguard-Peer-Manager wpm
$ cat > wg0.conf <<EOF
[Interface]
Address = 10.150.200.1/24
ListenPort = 51820
PrivateKey = $(wg genkey)
PostUp = iptables -A FORWARD -i %i -o %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o %i -j ACCEPT
SaveConfig = false
EOF

$ cd wpm

# install python and system requirements.
$ apt install qrencode python3-pip
$ pip3 install -r requirements.txt

# Create config. It's optionally.
$ cp wpm_example.conf wpm.conf

# CLI usage. Client configs saved into `clients/peer_name.{conf,-qr.png,-qr.txt}`
$ python3 gen.py --peer my-pc   # add a new peer `my-pc`
$ python3 gen.py --delete my-pc # delete peer `my-pc`
$ python3 gen.py --update       # just regenerate all configs in `clients/`

# Telegram bot usage
$ TG_TOKEN=1292121488:AAG... TG_ADMIN=<comma separated list of usernames> python3 bot.py

```

## Config
Key | Default | Description
------------ | ------------- | ------------
allowed_ips | 0.0.0.0 | allowed_ips for generated peer configs.
dns | 8.8.8.8 | DNS for peer configs
hostname | $(hostname -f) | server address for peer configs. May be an IP.
config | wg0 | WireGuard config to work with. 


## Telegram Interface

<img src="https://user-images.githubusercontent.com/4666566/117370133-cc31f000-ae7a-11eb-93fd-a390d2616da8.png" alt="drawing" width="450"/> <img src="https://user-images.githubusercontent.com/4666566/117377076-48323500-ae87-11eb-9602-a0cd3072ff53.png" alt="drawing" width="350"/>


