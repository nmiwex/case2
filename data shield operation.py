    # operation_data_shield.py
import re
import base64
import codecs
import binascii
import os
from datetime import datetime


def add_unique(to_add, lst):
    """
    adds something to the list if it is unique
    :param to_add: something to be added
    :param lst: some list
    :return:None
    """
    if to_add not in lst:
        lst.append(to_add)


#the Luhn algorithm
def luhn_algorithm(card):
    """
    Сheck cards for valid and invalid
    :param card: the line with the card number
    :type card: str
    :return: checksum % 10 == 0
    """
    digits = [int(d) for d in card]
    ood_digit = digits[::2]
    even_digit = digits[1::2]
    checksum = sum(even_digit)

    for d in ood_digit:
        d *= 2
        if d > 9:
            d -= 9
        checksum += d

    return checksum % 10 == 0


#card numbers
def find_and_validate_credit_cards(numbers):
    """
    Searches for bank card numbers
    :param numbers: text to search in
    :return: {'card numbers: {'valid': [], 'invalid': []}'}
    """
    result = {'valid': [], 'invalid': []}
    card_numbers = re.findall(r'(?<!\d)(\d{4}[\s./\\-]?\d{4}[\s./\\-]?\d{4}'
                              r'[\s./\\-]?\d{4})(?!\d)', numbers)

    for card in card_numbers:
        clean_card = re.sub(r'\D', '', card)

        if len(clean_card) == 16 and luhn_algorithm(clean_card):
            result['valid'].append(clean_card)
        else:
            result['invalid'].append(clean_card)

    return result


def find_secrets(text):
    patterns = {
        'password': re.compile(r'(?i)\b(password|passwd|pwd|парол\w*)\b\s*'
                               r'[:=]\s*["\']?([^"\']+)'), # пароли
        'api_key': re.compile(r'(?i)\b(api[_-]?key|apikey|client[_-]?key|'
                              r'secret[_-]?key)\b\s*[:=]\s*["\']?([^"\']+)'), # api ключи
        'token': re.compile(r'(?i)\b(token|access[_-]?token|refresh[_-]?token|'
                            r'id[_-]?token)\b\s*[:=]\s*["\']?([^"\']+)'), # токены
        'bearer': re.compile(r'(?i)Authorization:\s*Bearer\s+([A-Za-z0-9\-._~+/]+=*)'), # Bearer-токен
        'api_key2': re.compile(r'\b[A-Za-z0-9_\-]{32,}\b'),  # если нет названий перед ключами
        'google_api_key': re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), # google api ключ
        'jwt': re.compile(r'\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b'), # jwt токен
        'stripe_key': re.compile(r'\b(sk|pk)_(live|test)_[0-9a-zA-Z]{24,}\b'), # stripe ключи
    }

    results = {key: [] for key in patterns}

    for key, pattern in patterns.items():
        for match in pattern.finditer(main_text):
            if key == 'api_key2' or key == 'google_api_key' or key == 'jwt':
                results[key].append(match.group())
            else:
                results[key].append(match.group(2) if match.lastindex >= 2 else match.group(1))

    return results


def find_system_info(text):
    patterns = {
        'ipv4': re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\.){3}'
                           r'(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)\b'), # ipv4 адреса
        'ipv6': re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'), # ipv6 адреса
        'email': re.compile(r'\b[a-zA-Z0-9._%+-]+@'r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'), # email
        'files': re.compile(r'\b[A-Za-z]:\\(?:[^\\\n]+\\)*[^\\\n]*'), # пути файлов
        'filename': re.compile(r'(?i)\b[\w\-. ]+\.(?:txt|log|csv|json|xml|'
                               r'py|js|php|html|css|env|ini|conf)\b') #имена файлов
    }

    results = {key: [] for key in patterns}

    for key, pattern in patterns.items():
        for match in pattern.finditer(main_text):
             add_unique(match.group(), results[key])

    return results


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
            result['base64'].append(b64_str)
        except binascii.Error:
            result['base64'].append('Некорректный формат Base64')
        except UnicodeDecodeError:
            result['base64'].append('Ошибка декодирования')

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
            result['hex'].append(hex_str)
        except ValueError:
            result['hex'].append('Ошибка: нечетное количество символов '
                                 'или недопустимые знаки')
        except UnicodeDecodeError:
            result['hex'].append('Ошибка декодирования: '
                                 f'Содержит нечитаемые бинарные данные')

    #rot13
    for _ in re.finditer(r'ROT13:\s*([A-Za-z0-9 .,!?;:\'"\-\(\)]*)', text):
        rot = _.group(1)
        rot_str = codecs.decode(rot, 'rot13')
        result['rot13'].append(rot_str)
    return result


def analyze_logs(log_text):
    """
    Analyzes web server logs and detects possible attacks.
    :param log_text: full log text
    :type log_text: str
    :return: dictionary with detected attacks
    """

    result = {
        'sql_injections': [],
        'xss_attempts': [],
        'suspicious_user_agents': [],
        'failed_logins': []
    }

    sql_patterns = [
        r'\bor\s+1=1\b',
        r'\bunion\s+select\b',
        r'\bdrop\s+table\b',
        r'\bselect\s+\*\s+from\b',
        r'\'--'
    ]

    xss_patterns = [
        r'<script.*?>.*?</script>',
        r'javascript:',
        r'onerror=',
        r'alert\s*\('
    ]

    user_agent_patterns = [
        r'sqlmap',
        r'curl',
        r'wget',
        r'python-requests',
        r'nikto',
        r'bot'
    ]

    failed_login_patterns = [
        r'failed login',
        r'401',
        r'unauthorized',
        r'invalid password',
        r'authentication failed'
    ]

    lines = log_text.split('\n')

    for line in lines:
        for pattern in sql_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                add_unique(line.strip(), result['sql_injections'])
                break

        for pattern in xss_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                add_unique(line.strip(), result['xss_attempts'])
                break

        for pattern in user_agent_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                add_unique(line.strip(), result['suspicious_user_agents'])
                break

        for pattern in failed_login_patterns:
            if re.search(pattern, line, re.IGNORECASE):
                add_unique(line.strip(), result['failed_logins'])
                break

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
        m = re.match(r'^\s*(\d{1,2})\s*([А-Яа-я]+)\s*(\d{4})\s*$', d)
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
        '%d.%m.%Y', '%d/%m/%Y', '%d-%m-%Y', '%Y.%m.%d', '%Y-%m-%d',
        '%Y/%m/%d', '%m.%d.%Y', '%m/%d/%Y', '%m-%d-%Y', '%d %B %Y',
        '%d-%B-%Y', '%d %b %Y', '%d-%b-%Y'
    ]
    ru_month = {
        'янв': 1, 'января': 1, 'январь': 1,
        'фев': 2, 'февраля': 2, 'февраль': 2,
        'мар': 3, 'марта': 3, 'март': 3,
        'апр': 4, 'апреля': 4, 'апрель': 4,
        'май': 5, 'мая': 5,
        'июн': 6, 'июня': 6, 'июнь': 6,
        'июл': 7, 'июля': 7, 'июль': 7,
        'авг': 8, 'августа': 8, 'август': 8,
        'сен': 9, 'сент': 9, 'сентября': 9, 'сентябрь': 9,
        'окт': 10, 'октября': 10, 'октябрь': 10,
        'ноя': 11, 'ноября': 11, 'ноябрь': 11,
        'дек': 12, 'декабря': 12, 'декабрь': 12,
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

#card numbers
    for _ in re.finditer(r'Номер карты:\s*(\d{4}[\s./\\-]?\d{4}'
                              r'[\s./\\-]?\d{4}[\s./\\-]?\d{4})', text):
        card = _.group(0).strip()
        clean_card = re.sub(r'\D', '', card)

        if len(clean_card) == 16 and luhn_algorithm(clean_card):
            result['cards']['valid'].append(clean_card)
        else:
            result['cards']['invalid'].append(clean_card)

    return result

def generate_comprehensive_report(text):
    """Generate a full investigation report"""
    report_res = { 'financial_data': find_and_validate_credit_cards(text),
               'secrets': find_secrets(text),
               'system_info': find_system_info(text),
               'encoded_messages': decode_messages(text),
               'security_threats': analyze_logs(text),
               'normalized_data': normalize_and_validate(text)
               }
    return report_res


def print_report(report_data, file):
    """Demonstrate the report beautifully"""
    sections = [('ФИНАНСОВЫЕ ДАННЫЕ', report_data['financial_data']),
                ('СЕКРЕТНЫЕ КЛЮЧИ', report['secrets']),
                ('СИСТЕМНАЯ ИНФОРМАЦИЯ', report['system_info']),
                ('РАСШИФРОВАННЫЕ СООБЩЕНИЯ', report_data['encoded_messages']),
                ('УГРОЗЫ БЕЗОПАСНОСТИ', report['security_threats']),
                ('НОРМАЛИЗОВАННЫЕ ДАННЫЕ', report_data['normalized_data'])]

    file.write('=' * 50 + "ОТЧЕТ ОПЕРАЦИИ 'DATA SHIELD'" + '=' * 50)
    total_sum = []


    def find_artifacts(art, key=None):
        if art is None:
            file.write(f'\nНичего не найдено')
        if isinstance(art, dict):
            for k, v in art.items():
                if v:
                    file.write(f'\n✰{k.upper()}')
                find_artifacts(v, key=k)
            return
        elif isinstance(art, list):
            for item in art:
                find_artifacts(item)
            return
        elif isinstance(art, str):
            file.write(f'\n{len(total_sum)+1}. {art}')
            total_sum.append(art)


    for title, data in sections:
        file.write(f'\n{title}:')
        find_artifacts(data)
        file.write('\n' + '-' * 30)
    file.write(f'\n\tНайдено артефактов: {len(total_sum)} \n')
    file.write('=' * 50 + 'КОНЕЦ ОТЧЕТА' + '=' * 50)


def extract_artifacts(filename):
    artifacts = set()

    if not os.path.exists(filename):
        return artifacts

    with open(filename, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()

            if (
                not line or
                line.startswith('=') or
                line.startswith('-') or
                line.startswith('✰') or
                line.endswith(':') or
                'ОТЧЕТ' in line or
                'КОНЕЦ ОТЧЕТА' in line or
                'Найдено артефактов' in line
            ):
                continue

            artifacts.add(line)

    return artifacts



if __name__ == '__main__':
    with open('input1.txt', 'r', encoding='utf-8') as f:
        main_text = f.read()
        report = generate_comprehensive_report(main_text)
        with open('result1.txt', 'w', encoding='utf-8') as output_file:
            print_report(report, output_file)