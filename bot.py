#!/usr/bin/env python3
# Author: 'UltraDesu <ab@hexor.ru>'
# Home: https://github.com/house-of-vanity/Wireguard-Peer-Manager

import logging
import os
import sys
import configparser
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Updater, MessageHandler, CommandHandler, filters, CallbackQueryHandler, CallbackContext
from gen import add_peer as wg_add_peer
from gen import update_configs
from gen import list_peers as wg_list_peers
from gen import del_peer as wg_del_peer


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)
token = os.environ.get('TG_TOKEN')
admin = os.environ.get('TG_ADMIN').replace('"', '').replace(' ', '').split(',')
if not token or not admin:
    log.error("Env var TG_TOKEN or TG_ADMIN aren't set.")
    sys.exit(1)
wpm_config = configparser.ConfigParser()
if wpm_config.read('wpm.conf'):
    config = wpm_config['Interface'].get('config', 'wg0')
else:
    config = "wg0"

def _help(update, context):
    update.message.reply_text('<b>Help:</b>\n <b>*</b> /add <i>peer name</i>\n <b>*</b> /del <i>peer name</i>\n <b>*</b> /list [<i>peer name</i>]', parse_mode='HTML', disable_web_page_preview=True)

def auth(handler):
    def wrapper(update, context):
        if update.message.chat.username not in admin:
            update.message.reply_text(
                'You are not allowed to do that.', parse_mode='HTML', disable_web_page_preview=True)
            return False
        handler(update, context)
    return wrapper

@auth
def list_peers(update, context):
    if len(update.message.text.split()) == 1:
        n = 1
        message = "Peers:\n<code>"
        for peer in wg_list_peers():
            message += f"{n} * {peer['ip']}: {peer['name']}\n"
            n += 1
        update.message.reply_text(f"{message}</code>", parse_mode='HTML', disable_web_page_preview=True)
    else:
        peer_name = "_".join(update.message.text.split()[1:])
        if peer_name.isnumeric():
            n = 1
            for peer in wg_list_peers():
                if int(peer_name) == n:
                    peer_name = peer['name']
                    break
                n += 1
        try:
            msg = open(f'/etc/wireguard/clients_{config}/{peer_name}.conf', 'r').read()
            update.message.reply_photo(open(f'/etc/wireguard/clients_{config}/{peer_name}-qr.png', 'rb'), parse_mode='HTML', filename=f'{peer_name} QR.png', quote=True, caption=f"Install Wireguard VPN app and scan or open config.\n<code>{msg}</code>")
            update.message.reply_document(open(f'/etc/wireguard/clients_{config}/{peer_name}.conf', 'rb'))
        except:
            update.message.reply_text("Wrong client name.")

@auth
def del_peer(update, context):
    if len(update.message.text.split()) < 2:
        _help(update, context)
        return False
    peer_name = "_".join(update.message.text.split()[1:])
    log.info("Deleting peer %s", peer_name)
    wg_del_peer(peer_name)
    update.message.reply_text("Done.")

@auth
def add_peer(update, context):
    if len(update.message.text.split()) < 2:
        _help(update, context)
        return False
    peer_name = "_".join(update.message.text.split()[1:])
    log.info("Creating peer %s", peer_name)
    wg_add_peer(peer_name)
    msg = open(f'/etc/wireguard/clients_{config}/{peer_name}.conf', 'r').read()
    update.message.reply_photo(open(f'/etc/wireguard/clients_{config}/{peer_name}-qr.png', 'rb'), parse_mode='HTML', filename=f'{peer_name} QR.png', quote=True, caption=f"Install Wireguard VPN app and scan or open config.\n<code>{msg}</code>")
    update.message.reply_document(open(f'/etc/wireguard/clients_{config}/{peer_name}.conf', 'rb'))

def error(update, context):
    update.message.reply_text("Something went wrong...")

def main():
    updater = Updater(token, use_context=True)
    updater.dispatcher.add_error_handler(error)
    updater.dispatcher.add_handler(CommandHandler('add', add_peer))
    updater.dispatcher.add_handler(CommandHandler('list', list_peers))
    updater.dispatcher.add_handler(CommandHandler('del', del_peer))
    updater.dispatcher.add_handler(MessageHandler(filters.Filters.text, _help))
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    log = logging.getLogger('WireGuard-GenBot')
    main()


