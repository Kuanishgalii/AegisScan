import requests
import re
import logging
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger()

# Список популярных CMS
CMS_SIGNATURES = {
    "wordpress": {
        "file": "/wp-login.php",
        "meta_tag": '<meta name="generator" content="WordPress"',
        "header": 'X-Powered-By: WordPress'
    },
    "joomla": {
        "file": "/administrator/index.php",
        "meta_tag": '<meta name="generator" content="Joomla!">',
        "header": 'X-Powered-By: Joomla'
    },
    "drupal": {
        "file": "/user/login",
        "meta_tag": '<meta name="Generator" content="Drupal">',
        "header": 'X-Drupal-Cache: HIT'
    },
    "typo3": {
        "file": "/typo3/",
        "meta_tag": '<meta name="generator" content="TYPO3 CMS">',
        "header": 'X-TYPO3-Extension:'
    },
    "contao": {
        "file": "/contao/main.php",
        "meta_tag": '<meta name="generator" content="Contao">',
        "header": 'X-Contao-Cache:'
    },
    "bitrix": {
        "file": "/bitrix/",
        "meta_tag": '<meta name="generator" content="Bitrix">',
        "header": 'X-Bitrix:'
    },
    "modx": {
        "file": "/manager/",
        "meta_tag": '<meta name="generator" content="MODX Revolution">',
        "header": 'X-Powered-By: MODX'
    }
}

# Заголовки для проверки конфигурации сервера
HEADERS_TO_CHECK = [
    "X-Powered-By",  # Указывает на технологию (например, PHP, ASP.NET)
    "Server",  # Указывает на тип сервера (например, Apache, Nginx)
    "Strict-Transport-Security",  # Защита от MITM-атак
    "X-Content-Type-Options",  # Защита от неправильного типа контента
    "X-Frame-Options",  # Защита от clickjacking
    "X-XSS-Protection",  # Защита от XSS-атак
    "Content-Security-Policy"  # CSP — защита от атак
]

# Функция для проверки уязвимых путей
def check_vulnerable_paths(url):
    vulnerable_paths = ['/robots.txt', '/phpinfo.php', '/.git/config', '/.env']
    for path in vulnerable_paths:
        full_url = urljoin(url, path)
        try:
            response = requests.get(full_url, timeout=5)
            if response.status_code == 200:
                logger.warning(f"Найден уязвимый путь: {full_url}")
        except requests.RequestException:
            continue

# Функция для обнаружения CMS
def detect_cms(url):
    try:
        response = requests.get(url, timeout=5)
        # Проверяем наличие мета-тегов
        for cms, signatures in CMS_SIGNATURES.items():
            if signatures["meta_tag"] in response.text:
                logger.info(f"Обнаружена CMS {cms} по мета-тегу.")
                return cms
            # Проверяем наличие специфичного файла для каждой CMS
            if signatures["file"] in response.text or response.status_code == 200:
                logger.info(f"Обнаружена CMS {cms} по файлу {signatures['file']}.")
                return cms
            # Проверяем HTTP заголовки
            if signatures["header"] in response.headers:
                logger.info(f"Обнаружена CMS {cms} по заголовку {signatures['header']}.")
                return cms
    except requests.RequestException as e:
        logger.error(f"Ошибка при запросе {url}: {e}")
    return None

# Функция для проверки заголовков и конфигурации сервера
def check_server_headers(url):
    try:
        response = requests.get(url, timeout=5)
        for header in HEADERS_TO_CHECK:
            if header in response.headers:
                logger.info(f"Заголовок найден: {header}: {response.headers[header]}")
            else:
                logger.warning(f"Заголовок отсутствует: {header}")
        
        if response.status_code == 500:
            logger.warning(f"Ошибка 500 на сервере {url}: возможно, информация о сервере раскрыта.")
        elif response.status_code == 404:
            logger.info(f"Ошибка 404 на сервере {url}: это может указывать на неправильную настройку серверной конфигурации.")
        
    except requests.RequestException as e:
        logger.error(f"Ошибка при запросе {url}: {e}")

# Функция для поиска уязвимостей для CMS
def check_for_vulnerabilities(cms, url):
    vulnerabilities = {
        "wordpress": [
            "https://wpvulndb.com/",
            "https://www.cvedetails.com/vulnerability-list/vendor_id-74/product_id-100/"
        ],
        "joomla": [
            "https://www.joomla.org/announcements.html",
            "https://www.cvedetails.com/vulnerability-list/vendor_id-99/product_id-85/"
        ],
        "drupal": [
            "https://www.drupal.org/security",
            "https://www.cvedetails.com/vulnerability-list/vendor_id-27/product_id-194/"
        ],
        "typo3": [
            "https://typo3.org/security/",
            "https://www.cvedetails.com/vulnerability-list/vendor_id-242/product_id-859/"
        ],
        "contao": [
            "https://contao.org/en/security-advisories.html",
            "https://www.cvedetails.com/vulnerability-list/vendor_id-1761/product_id-17540/"
        ],
        "bitrix": [
            "https://www.bitrix24.com/support/",
            "https://www.cvedetails.com/vulnerability-list/vendor_id-6158/product_id-6157/"
        ],
        "modx": [
            "https://modx.com/security/",
            "https://www.cvedetails.com/vulnerability-list/vendor_id-4053/product_id-4052/"
        ]
    }
    
    if cms in vulnerabilities:
        logger.info(f"Проверка уязвимостей для {cms} на {url}...")
        for vuln_url in vulnerabilities[cms]:
            logger.info(f"Просмотр уязвимостей на {vuln_url}")

# Функция для сканирования сайта
def scan_website(url):
    # Многопоточность для ускорения сканирования
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = []
        
        # Проверка уязвимых путей
        futures.append(executor.submit(check_vulnerable_paths, url))
        
        # Проверка заголовков сервера
        futures.append(executor.submit(check_server_headers, url))
        
        # Обнаружение CMS
        futures.append(executor.submit(detect_cms, url))
        
        for future in futures:
            future.result()

# Пример использования
if __name__ == "__main__":
    test_url = "http://example.com"
    scan_website(test_url)
