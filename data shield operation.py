# operation_data_shield.py
import re
import base64
import codecs
import binascii
from datetime import datetime
with open('data_leak_sample.txt', 'r', encoding='utf-8') as f:
    main_text = f.read()


def add_unique(to_add, lst):
    """
    adds something to the list if it is unique
    :param to_add: something to be added
    :param lst: some list
    :return:None
    """
    if to_add not in lst:
        lst.append(to_add)


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
            result['hex'].append(f'{hex_code} -> Ошибка: нечетное количество'
                                 f' символов или недопустимые знаки')
        except UnicodeDecodeError:
            result['hex'].append(f'{hex_code} -> Ошибка декодирования: '
                                 f'Содержит нечитаемые бинарные данные')

    #rot13
    for _ in re.finditer(r'ROT13:\s*([A-Za-z0-9 .,!?;:\'"\-\(\)]*)', text):
        rot = _.group(1)
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
    #phones
    for _ in re.finditer(r'\b(\+7|8|7)[0-9 \(\)\-]{10,19}', text):
        phone = _.group(0)
        digits = re.sub(r'\D', '', phone)
        if len(digits) > 11:
            continue
        elif len(digits) == 11 and digits[0] in '78':
            if digits[0] == '8':
                digits = '7' + digits[1:]
            normalized_phone = (f'+{digits[0]} ({digits[1:4]}) '
                                f'{digits[4:7]}-{digits[7:9]}-{digits[9:]}')
            add_unique(normalized_phone, result['phones']['valid'])
        else:
            add_unique(phone, result['phones']['invalid'])
    for _ in re.finditer(r'\b9[0-9 \(\)\-]{9,16}', text):
        phone = _.group(0)
        digits = re.sub(r'\D', '', phone)
        if len(digits) != 10:
            continue
        normalized_phone = (f'+7 ({digits[:3]}) '
                            f'{digits[3:6]}-{digits[6:8]}-{digits[8:]}')
        add_unique(normalized_phone, result['phones']['valid'])

    #inn
    coef10 = [2, 4, 10, 3, 5, 9, 4, 6, 8]
    coef11 = [7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    coef12 = [3, 7, 2, 4, 10, 3, 5, 9, 4, 6, 8]
    for _ in re.finditer(r'\b(\d{10,13}[ \-]?)', text):
        inn = _.group(0)
        digits = re.sub(r'\D', '', inn)
        digits_int = list(map(int, digits))
        if len(digits) == 10:
            ctrl_sum = sum(digits_int[i] * coef10[i] for i in range(9))
            ctrl_digit = (ctrl_sum % 11) % 10
            if ctrl_digit == digits_int[-1]:
                add_unique(inn, result['inn']['valid'])
            else:
                add_unique(inn, result['inn']['invalid'])
        elif len(digits) == 12:
            ctrl_sum1 = sum(digits_int[i] * coef11[i] for i in range(10))
            ctrl_digit1 = (ctrl_sum1 % 11) % 10
            ctrl_sum2 = sum(digits_int[i] * coef12[i] for i in range(11))
            ctrl_digit2 = (ctrl_sum2 % 11) % 10
            if ctrl_digit1 == digits_int[-2] and ctrl_digit2 == digits_int[-1]:
                add_unique(digits, result['inn']['valid'])
            else:
                add_unique(digits, result['inn']['invalid'])

    #dates
    def parse_date(d):
        for fmt in formats:
            try:
                return datetime.strptime(d, fmt)
            except ValueError:
                continue
        m = re.match(r"^\s*(\d{1,2})\s*([А-Яа-я]+)\s*(\d{4})\s*$", d)
        if m:
            day = int(m.group(1))
            mon = m.group(2).lower()
            year = int(m.group(3))

            if mon in ru_month:
                month = ru_month[mon]
            else:
                mon3 = mon[:3]
                if mon3 in ru_month:
                    month = ru_month[mon3]
                else:
                    return None

            try:
                return datetime(year, month, day).date()
            except Exception:
                return None
        return None
    formats = [
        '%d.%m.%Y', '%d/%m/%Y', '%d-%m-%Y', '%Y.%m.%d', '%Y-%m-%d', '%Y/%m/%d',
        '%m.%d.%Y', '%m/%d/%Y', '%m-%d-%Y', '%d %B %Y', '%d-%B-%Y', '%d %b %Y', '%d-%b-%Y'
    ]
    ru_month = {
        "янв": 1, "января": 1, "январь": 1,
        "фев": 2, "февраля": 2, "февраль": 2,
        "мар": 3, "марта": 3, "март": 3,
        "апр": 4, "апреля": 4, "апрель": 4,
        "май": 5, "мая": 5,
        "июн": 6, "июня": 6, "июнь": 6,
        "июл": 7, "июля": 7, "июль": 7,
        "авг": 8, "августа": 8, "август": 8,
        "сен": 9, "сент": 9, "сентября": 9, "сентябрь": 9,
        "окт": 10, "октября": 10, "октябрь": 10,
        "ноя": 11, "ноября": 11, "ноябрь": 11,
        "дек": 12, "декабря": 12, "декабрь": 12,
    }
    for _ in re.finditer(r'\b\d{1,4}[^0][./-]\d{1,2}[./-]\d{2,4}\b|'
                         r'\b\d{1,2}[ \-][A-Za-zа-яА-Я]{3,}[ \-]\d{4}\b', text):
        date = _.group(0).strip()
        try:
            dt = parse_date(date)
            if dt is None:
                add_unique(date, result['dates']['invalid'])
            else:
                add_unique(dt.strftime('%d.%m.%Y'), result['dates']['normalized'])
        except ValueError:
            add_unique(date, result['dates']['invalid'])

    return result
print(normalize_and_validate(main_text))