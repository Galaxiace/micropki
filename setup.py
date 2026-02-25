from setuptools import setup, find_packages

setup(
    name="micropki",
    version="0.1.0",
    packages=find_packages(),
    install_requires=[
        "cryptography>=41.0.0",
    ],
)