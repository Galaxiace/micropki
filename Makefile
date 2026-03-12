.PHONY: help test clean install setup run-rsa run-ecc verify run create-dirs check-secrets \
        create-int-pass issue-intermediate issue-server issue-client issue-codesign \
        verify-chain test-sprint2 check-permissions check-structure

# Цвета для вывода
GREEN := \033[0;32m
RED := \033[0;31m
YELLOW := \033[0;33m
NC := \033[0m

# Создание необходимых папок
create-dirs:
	@echo "${YELLOW}Creating directories...${NC}"
	mkdir -vp logs
	mkdir -vp secrets
	mkdir -vp pki/private pki/certs pki/certs/csrs
	mkdir -vp pki-ecc/private pki-ecc/certs pki-ecc/certs/csrs
	@echo "${GREEN}✓ Directories created${NC}"
	@echo ""

# Проверка наличия файлов с паролями
check-secrets:
	@echo "${YELLOW}Checking secrets...${NC}"
	@if [ ! -f secrets/pass.txt ]; then \
		echo "${RED}✗ secrets/pass.txt not found!${NC}"; \
		echo "  Create it with: echo 'your_password' > secrets/pass.txt"; \
		exit 1; \
	else \
		echo "${GREEN}✓ secrets/pass.txt exists${NC}"; \
		ls -la secrets/pass.txt; \
	fi
	@if [ ! -f secrets/int.pass ]; then \
		echo "${YELLOW}⚠ secrets/int.pass not found. Creating with default password...${NC}"; \
		echo "intermediate456" > secrets/int.pass; \
		chmod 600 secrets/int.pass; \
		echo "${GREEN}✓ secrets/int.pass created${NC}"; \
	else \
		echo "${GREEN}✓ secrets/int.pass exists${NC}"; \
	fi
	@echo ""

# Создать пароль для Intermediate CA
create-int-pass:
	@echo "${YELLOW}Creating Intermediate CA password file...${NC}"
	@echo "intermediate456" > secrets/int.pass
	chmod 600 secrets/int.pass
	@echo "${GREEN}✓ secrets/int.pass created${NC}"
	@echo ""

help: ## Показать все доступные команды
	@printf "${GREEN}Available commands:${NC}\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${GREEN}%-20s${NC} %s\n", $$1, $$2}'

setup: ## Создать виртуальное окружение
	@echo "${YELLOW}Creating virtual environment...${NC}"
	python -m venv venv
	@echo "${GREEN}✓ Virtual environment created${NC}"
	@echo "Activate with: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)"

install: ## Установить зависимости
	@echo "${YELLOW}Installing dependencies...${NC}"
	pip install -r requirements.txt
	@echo "${GREEN}✓ Dependencies installed${NC}"

test: ## Запустить все тесты
	@echo "${YELLOW}Running all tests...${NC}"
	pytest tests/ -v
	@echo "${GREEN}✓ Tests completed${NC}"

test-sprint2: ## Запустить тесты Sprint 2
	@echo "${YELLOW}Running Sprint 2 tests...${NC}"
	pytest tests/test_sprint2_basic.py -v
	pytest tests/test_sprint2_negative.py -v
	pytest tests/test_sprint2_integration.py -v
	@echo "${GREEN}✓ Sprint 2 tests completed${NC}"

run-rsa: create-dirs check-secrets ## Создать RSA корневой CA
	@echo "${YELLOW}Creating RSA Root CA...${NC}"
	python -m micropki.cli ca init \
		--subject "/CN=Test RSA CA/O=MicroPKI/C=RU" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./secrets/pass.txt \
		--out-dir ./pki \
		--validity-days 3650 \
		--log-file ./logs/ca-init.log; \
	EXIT_CODE=$$?; \
	if [ $$EXIT_CODE -ne 0 ]; then \
		echo "${RED}Command failed with exit code $$EXIT_CODE${NC}"; \
		exit $$EXIT_CODE; \
	else \
		echo "${GREEN}✓ RSA CA creation completed successfully${NC}"; \
	fi

run-ecc: create-dirs check-secrets ## Создать ECC корневой CA
	@echo "${YELLOW}Creating ECC Root CA...${NC}"
	python -m micropki.cli ca init \
		--subject "/CN=Test ECC CA/O=MicroPKI/C=RU" \
		--key-type ecc \
		--key-size 384 \
		--passphrase-file ./secrets/pass.txt \
		--out-dir ./pki-ecc \
		--validity-days 3650 \
		--log-file ./logs/ca-init-ecc.log
	@echo "${GREEN}✓ ECC CA creation completed${NC}"

issue-intermediate: check-secrets ## Выпустить Intermediate CA (KEY-5)
	@echo "${YELLOW}Issuing Intermediate CA...${NC}"
	python -m micropki.cli ca issue-intermediate \
		--root-cert ./pki/certs/ca.cert.pem \
		--root-key ./pki/private/ca.key.pem \
		--root-pass-file ./secrets/pass.txt \
		--subject "/CN=Test Intermediate CA/O=MicroPKI" \
		--key-type rsa \
		--key-size 4096 \
		--passphrase-file ./secrets/int.pass \
		--out-dir ./pki \
		--validity-days 1825 \
		--pathlen 0 \
		--log-file ./logs/intermediate.log
	@echo "${GREEN}✓ Intermediate CA issued successfully${NC}"
	@echo ""

issue-server: ## Выпустить серверный сертификат (KEY-7)
	@echo "${YELLOW}Issuing Server Certificate...${NC}"
	python -m micropki.cli ca issue-cert \
		--ca-cert ./pki/certs/intermediate.cert.pem \
		--ca-key ./pki/private/intermediate.key.pem \
		--ca-pass-file ./secrets/int.pass \
		--template server \
		--subject "/CN=example.com" \
		--san dns:example.com \
		--san dns:www.example.com \
		--out-dir ./pki/certs \
		--validity-days 365 \
		--log-file ./logs/server.log
	@echo "${GREEN}✓ Server certificate issued${NC}"
	@echo ""

issue-client: ## Выпустить клиентский сертификат
	@echo "${YELLOW}Issuing Client Certificate...${NC}"
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
	@echo "${GREEN}✓ Client certificate issued${NC}"
	@echo ""

issue-codesign: ## Выпустить code signing сертификат
	@echo "${YELLOW}Issuing Code Signing Certificate...${NC}"
	python -m micropki.cli ca issue-cert \
		--ca-cert ./pki/certs/intermediate.cert.pem \
		--ca-key ./pki/private/intermediate.key.pem \
		--ca-pass-file ./secrets/int.pass \
		--template code_signing \
		--subject "/CN=MicroPKI Code Signer" \
		--out-dir ./pki/certs \
		--validity-days 365 \
		--log-file ./logs/codesign.log
	@echo "${GREEN}✓ Code signing certificate issued${NC}"
	@echo ""

verify-cert: ## Проверить сертификат (TEST-8)
	@echo "${YELLOW}Verifying certificate with OpenSSL...${NC}"
	@if [ -z "$(cert)" ]; then \
		echo "${RED}Usage: make verify-cert cert=path/to/cert.pem${NC}"; \
		exit 1; \
	fi
	openssl x509 -in $(cert) -text -noout | grep -A20 "X509v3 extensions"
	@echo ""
	openssl verify -CAfile ./pki/certs/ca.cert.pem $(cert)

verify-chain: ## Проверить цепочку сертификатов (TEST-7)
	@echo "${YELLOW}Verifying certificate chain...${NC}"
	python -m micropki.cli ca verify-chain \
		--leaf ./pki/certs/example.com.cert.pem \
		--intermediate ./pki/certs/intermediate.cert.pem \
		--root ./pki/certs/ca.cert.pem \
		--log-file ./logs/chain-verify.log

verify: ## Проверить корневой сертификат
	@echo "${YELLOW}Verifying Root CA certificate...${NC}"
	@if [ -f pki/certs/ca.cert.pem ]; then \
		echo "${GREEN}Certificate found:${NC}"; \
		openssl x509 -in pki/certs/ca.cert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After"; \
		echo "\n${GREEN}OpenSSL verification:${NC}"; \
		openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem; \
	else \
		echo "${RED}✗ Certificate not found. Run 'make run-rsa' first.${NC}"; \
	fi

verify-int: ## Проверить Intermediate CA (TEST-11)
	@echo "${YELLOW}Verifying Intermediate CA...${NC}"
	openssl verify -CAfile ./pki/certs/ca.cert.pem ./pki/certs/intermediate.cert.pem

verify-full: ## Проверить полную цепочку через OpenSSL (TEST-11)
	@echo "${YELLOW}Verifying full chain with OpenSSL...${NC}"
	openssl verify -CAfile ./pki/certs/ca.cert.pem \
		-untrusted ./pki/certs/intermediate.cert.pem \
		./pki/certs/example.com.cert.pem

negative-test-nosan: ## Негативный тест: сервер без SAN (должен упасть)
	@echo "${YELLOW}Running negative test: server cert without SAN${NC}"
	-python -m micropki.cli ca issue-cert \
		--ca-cert ./pki/certs/intermediate.cert.pem \
		--ca-key ./pki/private/intermediate.key.pem \
		--ca-pass-file ./secrets/int.pass \
		--template server \
		--subject "/CN=test.com" \
		--out-dir ./pki/certs \
		--validity-days 365 && \
		echo "${RED}✗ Test FAILED: Command should have failed${NC}" || \
		echo "${GREEN}✓ Test PASSED: Command failed as expected${NC}"

check-permissions: ## Проверить права доступа (KEY-5, KEY-7)
	@echo "${YELLOW}Checking file permissions...${NC}"
	@echo "Root key:"; ls -la pki/private/ca.key.pem 2>/dev/null || echo "Not found"
	@echo "Intermediate key:"; ls -la pki/private/intermediate.key.pem 2>/dev/null || echo "Not found"
	@echo "Server key:"; ls -la pki/certs/example.com.key.pem 2>/dev/null || echo "Not found"
	@echo "Private directory:"; ls -ld pki/private/ 2>/dev/null || echo "Not found"
	@echo ""

check-structure: ## Проверить структуру директорий (KEY-6)
	@echo "${YELLOW}Checking directory structure...${NC}"
	@tree pki/ 2>/dev/null || find pki -type d -o -type f | sort
	@echo ""

show-policy: ## Показать policy.txt
	@echo "${YELLOW}Policy document:${NC}"
	@cat pki/policy.txt 2>/dev/null || echo "Not found"

show-logs: ## Показать последние логи
	@echo "${YELLOW}Recent logs:${NC}"
	@ls -lt logs/ | head -10

run-full: run-rsa issue-intermediate issue-server issue-client issue-codesign ## Полный цикл: Root -> Intermediate -> все сертификаты
	@echo "${GREEN}✓ Full Sprint 2 workflow completed${NC}"

clean: ## Очистить временные файлы
	@echo "${YELLOW}Cleaning up...${NC}"
	# Удаляем сгенерированные файлы
	rm -rvf pki/
	rm -rvf pki-ecc/
	rm -rvf logs/
	# Удаляем кэш Python
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	# Удаляем кэш тестов
	rm -rf .pytest_cache
	rm -rf .coverage
	rm -rf htmlcov/
	@echo "${GREEN}✓ Clean completed${NC}"
	@echo "${YELLOW}Note: secrets/pass.txt and secrets/int.pass were NOT deleted${NC}"

run: run-rsa ## Создать RSA CA (по умолчанию)