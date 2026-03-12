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
mkdir -p secrets logs

# Root CA пароль (один)
echo "rootSecurePassword123" > secrets/pass.txt

# Intermediate CA пароль (ДРУГОЙ, для безопасности)
echo "intermediateSecurePassword456" > secrets/int.pass

# Установка правильных прав доступа
chmod 600 secrets/*.pass
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

### Создание промежуточного CA (Intermediate CA)

```bash

python -m micropki.cli ca issue-intermediate \
  --root-cert ./pki/certs/ca.cert.pem \
  --root-key ./pki/private/ca.key.pem \
  --root-pass-file ./secrets/pass.txt \
  --subject "/CN=My Intermediate CA/O=MicroPKI" \
  --key-type rsa \
  --key-size 4096 \
  --passphrase-file ./secrets/int.pass \
  --out-dir ./pki \
  --validity-days 1825 \
  --pathlen 0 \
  --log-file ./logs/intermediate.log
```

### Выпуск серверного сертификата

```bash

python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/int.pass \
  --template server \
  --subject "/CN=example.com" \
  --san dns:example.com \
  --san dns:www.example.com \
  --san ip:192.168.1.100 \
  --out-dir ./pki/certs \
  --validity-days 365 \
  --log-file ./logs/server.log
```

### Выпуск клиентского сертификата

```bash

python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/int.pass \
  --template client \
  --subject "/CN=Alice Smith/emailAddress=alice@example.com" \
  --san email:alice@example.com \
  --san dns:client.example.com \
  --out-dir ./pki/certs \
  --validity-days 365 \
  --log-file ./logs/client.log
```

### Выпуск code signing сертификата

```bash

python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/int.pass \
  --template code_signing \
  --subject "/CN=MicroPKI Code Signer" \
  --out-dir ./pki/certs \
  --validity-days 365 \
  --log-file ./logs/codesign.log
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

### Проверка полной цепочки сертификатов

```bash

python -m micropki.cli ca verify-chain \
  --leaf ./pki/certs/example.com.cert.pem \
  --intermediate ./pki/certs/intermediate.cert.pem \
  --root ./pki/certs/ca.cert.pem \
  --log-file ./logs/chain-verify.log
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

### Проверка промежуточного CA

```bash

openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/intermediate.cert.pem
```

### Проверка полной цепочки

```bash

openssl verify -CAfile ./pki/certs/ca.cert.pem \
  -untrusted ./pki/certs/intermediate.cert.pem \
  ./pki/certs/example.com.cert.pem
```

### Проверка расширений серверного сертификата

```bash

openssl x509 -in ./pki/certs/example.com.cert.pem -text -noout | grep -A20 "X509v3 extensions"
```

### Проверка расширений корневого сертификата

```bash

openssl x509 -in pki/certs/ca.cert.pem -text -noout | grep -A1 "X509v3 Basic Constraints"
openssl x509 -in pki/certs/ca.cert.pem -text -noout | grep -A1 "X509v3 Key Usage"
```

### Просмотр policy документа

```bash

cat pki/policy.txt
```

## Негативные тесты (проверка ошибок)

### Попытка выпустить серверный сертификат без SAN (должна упасть)

```bash

python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/int.pass \
  --template server \
  --subject "/CN=test.com" \
  --out-dir ./pki/certs \
  --validity-days 365
# Ожидается ошибка: "Template server requires at least one SAN"
```

### Попытка использовать неправильный пароль

```bash

python -m micropki.cli ca issue-cert \
  --ca-cert ./pki/certs/intermediate.cert.pem \
  --ca-key ./pki/private/intermediate.key.pem \
  --ca-pass-file ./secrets/wrong.pass \
  --template server \
  --subject "/CN=example.com" \
  --san dns:example.com \
  --out-dir ./pki/certs \
  --validity-days 365
# Ожидается ошибка пароля
```

---

## Структура проекта

```
micropki/                            # Корневая папка проекта
│
├── micropki/                        # Основной пакет с кодом
│   ├── __init__.py                  # Инициализация пакета, версия
│   ├── cli.py                       # Интерфейс командной строки
│   ├── chain.py                     # Проверка цепочек сертификатов (leaf -> intermediate -> root)
│   ├── csr.py                       # Генерация и подпись CSR для Intermediate CA и внешних запросов
│   ├── templates.py                 # Шаблоны сертификатов (server/client/code_signing) с валидацией SAN и X.509 расширениями
│   ├── ca.py                        # Логика создания корневого CA
│   ├── crypto_utils.py              # Криптографические утилиты
│   ├── logger.py                    # Настройка логирования
│   └── verification.py              # Верификация сертификатов
│
├── tests/                           # Директория для тестов
│   ├── conftest.py
│   ├── test_basic.py                # Базовые юнит-тесты
│   ├── test_errors.py               # Тесты негативных сценариев
│   ├── test_key_cert_match.py       # Тесты соответствия ключей
│   ├── test_sprint2_basic.py        # Юнит-тесты шаблонов, CSR, SAN парсинга
│   ├── test_sprint2_integration.py  # Интеграционные тесты цепочек и OpenSSL совместимости
│   ├── test_sprint2_negative.py     # Негативные тесты (ошибки валидации, пароли, CSR с CA=true)
│   └── test_sprint2_roundtrip.py    # Round-trip тест TLS соединения с выпущенным сертификатом
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

### Создание промежуточного CA

```bash

make issue-intermediate # Создать Intermediate CA (требует run-rsa)
```

### Выпуск сертификатов

```bash

make issue-server       # Выпустить серверный сертификат
make issue-client       # Выпустить клиентский сертификат
make issue-codesign     # Выпустить code signing сертификат
```

### Полный цикл Root CA -> Intermediate CA -> все сертификаты

```bash

make run-full
```

### Проверка сертификатов

```bash

make verify             # Проверить корневой сертификат
make verify-int         # Проверить Intermediate CA через OpenSSL
make verify-full        # Проверить полную цепочку через OpenSSL
make verify-chain       # Проверить цепочку сертификатов
```

### Проверка структуры и прав доступа

```bash

make check-structure    # Показать структуру директорий
make check-permissions  # Проверить права доступа к ключам
make show-policy        # Показать policy.txt
make show-logs          # Показать последние логи
```

### Негативные тесты

```bash

make negative-test-nosan  # Тест: серверный сертификат без SAN (должен упасть)
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