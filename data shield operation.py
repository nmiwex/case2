# operation_data_shield.py
import re
import base64
import codecs
import binascii
with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
    main_text = f.read()


def add_unique(to_add, list):
    """
    adds something to the list if it is unique
    :param to_add: something to be added
    :param list: some list
    :return:None
    """
    if to_add not in list:
        list.append(to_add)


def decode_messages(text):
    """
    finds and decrypts messages
    :param text: text to decode
    :return: {'base64': [], 'hex': [], 'rot13': []}
    """
    result = {
        'base64': [],
        'hex': [],
        'rot13': []
    }
    #base64 codes
    for _ in re.finditer(r'Base64:\s*([A-Za-z0-9+/=]+)', text):
        b64 = _.group(1)
        try:
            b64_bytes = base64.b64decode(b64)
            b64_str =b64_bytes.decode('utf-8')
            result['base64'].append(f'{b64} -> {b64_str}')
        except binascii.Error:
            result['base64'].append(f'{b64} -> Некорректный формат Base64')
        except UnicodeDecodeError:
            result['base64'].append(f'{b64} -> Ошибка декодирования')

    #hex 0x.. codes
    hex_type1 = re.findall(r'Hex:\s*(0x[0-9A-Fa-f]+)', text)
    #hex \xHH.. codes
    hex_type2 = re.findall(r'(?:\\x[0-9A-Fa-f]{2})+', text)
    all_hex = hex_type1 + hex_type2
    for hex_code in all_hex:
        try:
            clean_hex = hex_code.replace('0x', '').replace('\\x', '')
            hex_bytes = bytes.fromhex(clean_hex)
            hex_str = hex_bytes.decode('utf-8')
            result['hex'].append(f'{hex_code} -> {hex_str}')
        except ValueError:
            result['hex'].append(f'{hex_code} -> Ошибка: нечетное количество символов или недопустимые знаки"')
        except UnicodeDecodeError:
            result['hex'].append(f'{hex_code} -> Ошибка декодирования: Содержит нечитаемые бинарные данные')

    #rot13
    for _ in re.finditer(r'ROT13:\s*([A-Za-z0-9 .,!?;:\'"\-\(\)]*)', text):
        rot = _.group(1)
        rot_str = codecs.decode(rot, 'rot13')
        result['rot13'].append(f'{rot} -> {rot_str}')
    return result
print(decode_messages(main_text))

def normalize_and_validate(text):
    """
    Brings the data to a single format and check it
    :param text: text to normalize
    :return: {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }
    """
    result = {
        'phones': {'valid': [], 'invalid': []},
        'dates': {'normalized': [], 'invalid': []},
        'inn': {'valid': [], 'invalid': []},
        'cards': {'valid': [], 'invalid': []}
    }
    #phones
    for _ in re.finditer(r'\b(\+7|8|7)[0-9 \(\)\-]{10,19}', text):
        phone = _.group(0)
        digits = re.sub(r'\D', '', phone)
        if len(digits) > 11:
            continue
        elif len(digits) == 11 and digits[0] in '78':
            if digits[0] == '8':
                digits = '7' + digits[1:]
            normalized_phone = f'+{digits[0]} ({digits[1:4]}) {digits[4:7]}-{digits[7:9]}-{digits[9:]}'
            add_unique(normalized_phone, result['phones']['valid'])
        else:
            add_unique(phone, result['phones']['invalid'])
    for _ in re.finditer(r'\b9[0-9 \(\)\-]{9,16}', text):
        phone = _.group(0)
        digits = re.sub(r'\D', '', phone)
        if len(digits) != 10:
            continue
        normalized_phone = f'+7 ({digits[:3]}) {digits[3:6]}-{digits[6:8]}-{digits[8:]}'
        add_unique(normalized_phone, result['phones']['valid'])
    return result
print(normalize_and_validate(main_text))