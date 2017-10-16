from setuptools import setup

setup(
    name = 'aggregate_signature',
    version = '0.1',
    packages = ['aggregate_signature'],
    install_requires = [
        'petlib',
        'numpy'
    ],
)