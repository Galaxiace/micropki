import pytest
import subprocess
import tempfile
import os
from pathlib import Path


def run_micropki_ca_init(args):
    """Helper function to run micropki ca init with given args"""
    cmd = ['python', '-m', 'micropki.cli', 'ca', 'init'] + args
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result


def test_missing_subject():
    """TEST-4: Missing --subject should fail"""
    result = run_micropki_ca_init([
        '--key-type', 'rsa',
        '--key-size', '4096',
        '--passphrase-file', 'secrets/pass.txt'
    ])
    assert result.returncode != 0
    # Проверяем, что в stderr есть сообщение об ошибке от argparse
    assert 'error: the following arguments are required: --subject' in result.stderr


def test_wrong_key_size_for_ecc():
    """TEST-4: ECC with key-size 256 should fail"""
    result = run_micropki_ca_init([
        '--subject', '/CN=Test',
        '--key-type', 'ecc',
        '--key-size', '256',
        '--passphrase-file', 'secrets/pass.txt'
    ])
    assert result.returncode != 0
    # Проверяем наше сообщение об ошибке валидации
    assert 'ECC key size must be 384 bits' in result.stderr or 'ECC key size must be 384 bits' in result.stdout


def test_nonexistent_passphrase_file():
    """TEST-4: Non-existent passphrase file should fail"""
    result = run_micropki_ca_init([
        '--subject', '/CN=Test',
        '--key-type', 'rsa',
        '--key-size', '4096',
        '--passphrase-file', './secrets/nonexistent.txt'
    ])
    assert result.returncode != 0
    # Проверяем наше сообщение об ошибке валидации
    assert 'Passphrase file does not exist' in result.stderr or 'Passphrase file does not exist' in result.stdout


def test_unwritable_out_dir():
    """TEST-4: Unwritable output directory should fail"""
    with tempfile.TemporaryDirectory() as tmpdir:
        # Create a file instead of directory (unwritable as out-dir)
        unwritable = Path(tmpdir) / 'test'
        unwritable.touch()
        os.chmod(unwritable, 0o444)  # Read-only

        result = run_micropki_ca_init([
            '--subject', '/CN=Test',
            '--key-type', 'rsa',
            '--key-size', '4096',
            '--passphrase-file', 'secrets/pass.txt',
            '--out-dir', str(unwritable)
        ])
        assert result.returncode != 0
        # Проверяем наше сообщение об ошибке
        assert 'Output directory is not writable' in result.stderr or 'Output directory is not writable' in result.stdout


def test_invalid_key_type():
    """TEST-4: Invalid key type should fail"""
    cmd = ['python', '-m', 'micropki.cli', 'ca', 'init',
           '--subject', '/CN=Test',
           '--key-type', 'invalid',
           '--key-size', '4096',
           '--passphrase-file', 'secrets/pass.txt']
    result = subprocess.run(cmd, capture_output=True, text=True)
    assert result.returncode != 0
    # Проверяем ошибку от argparse (invalid choice)
    assert "invalid choice: 'invalid'" in result.stderr or "invalid choice: 'invalid'" in result.stdout


def test_negative_validity_days():
    """TEST-4: Negative validity days should fail"""
    result = run_micropki_ca_init([
        '--subject', '/CN=Test',
        '--key-type', 'rsa',
        '--key-size', '4096',
        '--passphrase-file', 'secrets/pass.txt',
        '--validity-days', '-1'
    ])
    assert result.returncode != 0
    # Проверяем наше сообщение об ошибке валидации
    assert 'Validity days must be positive' in result.stderr or 'Validity days must be positive' in result.stdout


def test_empty_subject():
    """TEST-4: Empty subject should fail"""
    result = run_micropki_ca_init([
        '--subject', '',
        '--key-type', 'rsa',
        '--key-size', '4096',
        '--passphrase-file', 'secrets/pass.txt'
    ])
    assert result.returncode != 0
    # Проверяем наше сообщение об ошибке валидации
    assert '--subject must be provided and non-empty' in result.stderr or '--subject must be provided and non-empty' in result.stdout


def test_wrong_key_size_for_rsa():
    """TEST-4: RSA with wrong key size should fail"""
    result = run_micropki_ca_init([
        '--subject', '/CN=Test',
        '--key-type', 'rsa',
        '--key-size', '2048',  # Wrong size, should be 4096
        '--passphrase-file', 'secrets/pass.txt'
    ])
    assert result.returncode != 0
    # Проверяем наше сообщение об ошибке валидации
    assert 'RSA key size must be 4096 bits' in result.stderr or 'RSA key size must be 4096 bits' in result.stdout