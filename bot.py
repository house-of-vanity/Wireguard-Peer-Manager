import logging
import os
import sys
from telegram import InlineKeyboardButton, InlineKeyboardMarkup, Update
from telegram.ext import Updater, MessageHandler, CommandHandler, filters, CallbackQueryHandler, CallbackContext
from gen import add_peer as wg_add_peer
from gen import update_configs


logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
log = logging.getLogger(__name__)
token = os.environ.get('TG_TOKEN')
admin = os.environ.get('TG_ADMIN')
if not token or not admin:
    log.error("Env var TG_TOKEN or TG_ADMIN aren't set.")
    sys.exit(1)

def _help(update, context):
    update.message.reply_text('<b>Help:</b>\n <b>*</b> /add <i>peer name</i>', parse_mode='HTML', disable_web_page_preview=True)

def add_peer(update, context):
    if update.message.chat.username != admin:
        update.message.reply_text('You are not allowed to do that.', parse_mode='HTML', disable_web_page_preview=True)
        return False
    if len(update.message.text.split()) < 2:
        update.message.reply_text('Wrong usage.\n<b>Help:</b>\n <b>*</b> /add <i>peer name</i>', parse_mode='HTML', disable_web_page_preview=True)
        return False
    log.info(update.message.chat.username)
    peer_name = "_".join(update.message.text.split()[1:])
    log.info("Creating peer %s", peer_name)
    wg_add_peer(peer_name)
    update.message.reply_photo(open(f'clients/{peer_name}-qr.png', 'rb'), filename=f'{peer_name} QR.png', quote=True, caption=open(f'clients/{peer_name}.conf', 'r').read())


def main():
    updater = Updater(token, use_context=True)
    updater.dispatcher.add_handler(CommandHandler('add', add_peer))
    updater.dispatcher.add_handler(MessageHandler(filters.Filters.text, _help))
    updater.start_polling()
    updater.idle()

if __name__ == '__main__':
    log = logging.getLogger('WireGuard-GenBot')
    main()


