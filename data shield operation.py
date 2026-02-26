# operation_data_shield.py
import re
import base64
import codecs
with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
    main_text = f.read()


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
    b64_codes = re.findall(r'Base64:\s*([A-Za-z0-9+/=]+)', text)
    for b64 in b64_codes:
        try:
            b64_bytes = base64.b64decode(b64)
            b64_str =b64_bytes.decode('utf-8')
            result['base64'].append(f'{b64} -> {b64_str}')
        except Exception:
            result['base64'].append(f'{b64} -> Ошибка декодирования!')

    #hex 0x.. codes
    hex_type1 = re.findall(r'Hex:\s*(0x[0-9A-Fa-f]+)', text)
    #hex \xHH.. codes
    hex_type2 = re.findall(r'(?:\\x[0-9A-Fa-f]{2})+', text)
    for hex_code in hex_type1:
        try:
            clean_hex = hex_code.replace('0x', '')
            hex_bytes = bytes.fromhex(clean_hex)
            hex_str = hex_bytes.decode('utf-8')
            result['hex'].append(f'{hex_code} -> {hex_str}')
        except Exception:
            result['hex'].append(f'{hex_code} -> Ошибка декодирования!')
    for hex_code in hex_type2:
        try:
            clean_hex = hex_code.replace('\\x', '')
            hex_bytes = bytes.fromhex(clean_hex)
            hex_str = hex_bytes.decode('utf-8')
            result['hex'].append(f'{hex_code} -> {hex_str}')
        except Exception:
            result['hex'].append(f'{hex_code} -> Ошибка декодирования!')

    #rot13
    rot_codes = re.findall(r'ROT13:\s*([A-Za-z0-9\s.,!?;:\'"\-\(\)]*)', text)
    for rot in rot_codes:
        rot_str = codecs.decode(rot, 'rot13')
        result['rot13'].append(f'{rot} -> {rot_str}')
    return result


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