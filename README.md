# MicroPKI - Minimal Public Key Infrastructure

*MicroPKI - это минимальная инфраструктура публичных ключей (PKI) для создания самоподписанных корневых центров сертификации (Root CA). Проект реализует базовые требования к созданию и управлению корневыми сертификатами с акцентом на безопасность и соответствие стандартам X.509.*

---

## Возможности

- **Генерация ключей**: Поддержка RSA-4096 и ECC P-384 (NIST)
- **Самоподписанные сертификаты**: X.509 v3 с правильными расширениями
- **Безопасное хранение**: Зашифрованные ключи (PKCS#8) с правильными правами доступа
- **Логирование**: Детальное логирование с временными метками
- **Policy документ**: Автоматическая генерация policy.txt с информацией о CA
- **Верификация**: Встроенная проверка сертификатов через OpenSSL
- **Тестирование**: Полный набор тестов (юнит-тесты, негативные сценарии, интеграционные тесты)

---

## Быстрый старт

### Предварительные требования

- Python 3.8 или выше
- OpenSSL (для верификации сертификатов)
- Git

## Установка

### Клонирование репозитория

```bash

git clone https://github.com/Galaxiace/micropki.git
```

### Переход в папку проекта

```bash

cd micropki
```

### Создание виртуального окружения

```bash

python -m venv venv
```

### Активация виртуального окружения

* ### На Linux/Mac:

```bash

source venv/bin/activate
```

* ### На Windows:

```bash

venv\Scripts\activate
```

### Установка зависимостей

```bash

pip install -r requirements.txt
```

### Установка пакета в режиме разработки (опционально)

```bash

pip install -e .
```

### Создание файла с паролем

```bash

# Создание папки для секретов
mkdir -p secrets

# Создание файла с паролем
echo "mySecurePassword123" > secrets/pass.txt

# Установка правильных прав доступа
chmod 600 secrets/pass.txt
```

---

## Использование

### Создание корневого CA (RSA)

```bash

# Создать папку для логов
mkdir -p logs

python -m micropki.cli ca init \
  --subject "/CN=My Root CA/O=MicroPKI/C=RU" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./secrets/pass.txt \
  --out-dir ./pki \
  --validity-days 3650 \
  --log-file ./logs/ca-init.log
```

### Создание корневого CA (ECC)

```bash

python -m micropki.cli ca init \
  --subject "/CN=My ECC Root CA/O=MicroPKI/C=RU" \
  --key-type ecc \
  --key-size 384 \
  --passphrase-file ./secrets/pass.txt \
  --out-dir ./pki-ecc \
  --validity-days 3650
```

### Верификация сертификата

```bash

# Проверка созданного сертификата
python -m micropki.cli ca verify --cert pki/certs/ca.cert.pem
```

### Верификация сертификата с сохранением логов

```bash

python -m micropki.cli ca verify \
  --cert pki/certs/ca.cert.pem \
  --log-file ./logs/verify.log
```

---

## Проверка через OpenSSL

### Просмотр информации о сертификате

```bash

# Просмотр информации о сертификате
openssl x509 -in pki/certs/ca.cert.pem -text -noout
```

### Проверка самоподписанного сертификата

```bash

openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem
```

### Проверка расширений

```bash

openssl x509 -in pki/certs/ca.cert.pem -text -noout | grep -A1 "X509v3 Basic Constraints"
openssl x509 -in pki/certs/ca.cert.pem -text -noout | grep -A1 "X509v3 Key Usage"
```

---

## Структура проекта

```
micropki/                           # Корневая папка проекта
│
├── micropki/                       # Основной пакет с кодом
│   ├── __init__.py                 # Инициализация пакета, версия
│   ├── cli.py                      # Интерфейс командной строки
│   ├── ca.py                       # Логика создания корневого CA
│   ├── crypto_utils.py             # Криптографические утилиты
│   ├── logger.py                   # Настройка логирования
│   └── verification.py             # Верификация сертификатов
│
├── tests/                           # Директория для тестов
│   ├── test_basic.py                # Базовые юнит-тесты
│   ├── test_errors.py               # Тесты негативных сценариев
│   └── test_key_cert_match.py       # Тесты соответствия ключей
│
├── .gitignore                       # Игнорируемые файлы Git
├── requirements.txt                 # Зависимости проекта
├── Makefile                         # Автоматизация задач
├── setup.py                         # Установка пакета
└── README.md                        # Документация проекта
```

---

## Тестирование

### Запуск всех тестов с подробным выводом

```bash

pytest tests/ -v
```

---

## Использование Makefile

### Показать все доступные команды

```bash

make help
```

### Создать виртуальное окружение

```bash

make setup
```

### Установить зависимости

```bash

make install
```

### Запустить тесты

```bash

make test
```

### Создать RSA корневой CA

```bash

make run-rsa
```

### Создать ECC корневой CA

```bash

make run-ecc
```

### Проверить сертификат

```bash

make verify
```

### Очистить временные файлы

```bash

make clean
```

---

## Безопасность

* Ключи шифруются с использованием PKCS#8 (AES-256)

* Права доступа: Ключи - 600, папка private - 700

* Серийные номера: 160 бит случайности (CSPRNG)

* Пароли никогда не логируются

* X.509 расширения: Все критические помечены как critical

---