.PHONY: help test clean install setup run-rsa run-ecc verify run create-dirs check-secrets

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
	mkdir -vp pki/private pki/certs
	mkdir -vp pki-ecc/private pki-ecc/certs
	@echo "${GREEN}✓ Directories created${NC}"
	@echo ""

# Проверка наличия файла с паролем
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
	@echo ""

help: ## Показать все доступные команды
	@printf "${GREEN}Available commands:${NC}\n"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  ${GREEN}%-15s${NC} %s\n", $$1, $$2}'

setup: ## Создать виртуальное окружение
	@echo "${YELLOW}Creating virtual environment...${NC}"
	python -m venv venv
	@echo "${GREEN}✓ Virtual environment created${NC}"
	@echo "Activate with: source venv/bin/activate (Linux/Mac) or venv\\Scripts\\activate (Windows)"

install: ## Установить зависимости
	@echo "${YELLOW}Installing dependencies...${NC}"
	pip install -r requirements.txt
	@echo "${GREEN}✓ Dependencies installed${NC}"

test: ## Запустить тесты
	@echo "${YELLOW}Running tests...${NC}"
	pytest tests/ -v
	@echo "${GREEN}✓ Tests completed${NC}"

run-rsa: create-dirs check-secrets ## Создать RSA корневой CA
	@echo "${YELLOW}Creating RSA Root CA...${NC}"
	@echo "Command: python -m micropki.cli ca init \\"
	@echo "        --subject '/CN=Test RSA CA' \\"
	@echo "        --key-type rsa \\"
	@echo "        --key-size 4096 \\"
	@echo "        --passphrase-file ./secrets/pass.txt \\"
	@echo "        --out-dir ./pki \\"
	@echo "        --validity-days 3650 \\"
	@echo "        --log-file ./logs/ca-init.log"
	@echo ""
	python -m micropki.cli ca init \
		--subject "/CN=Test RSA CA" \
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
	@echo "Command: python -m micropki.cli ca init \\"
	@echo "        --subject '/CN=Test ECC CA' \\"
	@echo "        --key-type ecc \\"
	@echo "        --key-size 384 \\"
	@echo "        --passphrase-file ./secrets/pass.txt \\"
	@echo "        --out-dir ./pki-ecc \\"
	@echo "        --validity-days 3650 \\"
	@echo "        --log-file ./logs/ca-init-ecc.log"
	@echo ""
	python -m micropki.cli ca init \
		--subject "/CN=Test ECC CA" \
		--key-type ecc \
		--key-size 384 \
		--passphrase-file ./secrets/pass.txt \
		--out-dir ./pki-ecc \
		--validity-days 3650 \
		--log-file ./logs/ca-init-ecc.log
	@echo "${GREEN}✓ ECC CA creation completed${NC}"

verify: ## Проверить сертификат
	@echo "${YELLOW}Verifying certificate...${NC}"
	@if [ -f pki/certs/ca.cert.pem ]; then \
		echo "${GREEN}Certificate found:${NC}"; \
		openssl x509 -in pki/certs/ca.cert.pem -text -noout | grep -E "Subject:|Issuer:|Not Before|Not After"; \
		echo "\n${GREEN}OpenSSL verification:${NC}"; \
		openssl verify -CAfile pki/certs/ca.cert.pem pki/certs/ca.cert.pem; \
	else \
		echo "${RED}✗ Certificate not found. Run 'make run-rsa' first.${NC}"; \
	fi

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
	@echo "${YELLOW}Note: secrets/pass.txt was NOT deleted (keep your password)${NC}"

run: run-rsa ## Создать RSA CA (по умолчанию)