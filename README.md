# Wireguard-Peer-Manager
![image](https://user-images.githubusercontent.com/4666566/117325184-56f7f800-ae45-11eb-9003-b85aadbf5ff0.png)

Adds Wireguard peers to config, reload it and send client config back via Telegram. 

**FYI: That tool stores client private keys into server config as comments.**
Is a good idea to update https://github.com/house-of-vanity/Wireguard-Peer-Manager/blob/b914707e06f807b4e57f1c1fa0ffcf903347b013/gen.py#L89

How to use:

```shell
# create initial wg config or use your own.
# P.S. Keep in mind that WPM can't manage peers created my hands
# due to absence of client private key.
$ cd /etc/wireguard && mkdir clients
$ cat > wg0.conf <<EOF
[Interface]
Address = 10.150.200.1/24
ListenPort = 51820
PrivateKey = $(wg genkey)
PostUp = iptables -A FORWARD -i %i -o %i -j ACCEPT
PostDown = iptables -D FORWARD -i %i -o %i -j ACCEPT
SaveConfig = false
EOF

# install python and system requirements.
$ pip3 install -r requirements.txt
$ apt install qrencode

# CLI usage. Client configs saved into `clients/peer_name.{conf,-qr.png,-qr.txt}`
$ python3 gen.py --peer my-pc # add a new peer `my-pc`
$ python3 gen.py --update     # just regenerate all configs in `clients/`

# Telegram bot usage
$ TG_TOKEN=1292121488:AAG... TG_ADMIN=<your_username> python3 bot.py
```

