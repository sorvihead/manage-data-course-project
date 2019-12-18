import json
import requests
from app import current_app


def translate(text, dest_language):
    if 'YANDEX_TRANSLATOR_KEY' not in current_app.config or \
            not current_app.config['YANDEX_TRANSLATOR_KEY']:
        return "Error: translation service is not configured"
    r = requests.post(f'https://translate.yandex.net/api/v1.5/tr.json/translate'
                      f'?key={current_app.config["YANDEX_TRANSLATOR_KEY"]}'
                      f'&text={text}'
                      f'&lang={dest_language}')
    if r.status_code != 200:
        return "Error: translation server failed"
    return json.loads(r.content.decode('utf-8-sig'))