import os
from setuptools import setup
# from distutils.core import setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

setup(
    name='django-secure',
    version='0.0.0',
    packages=['djangosecure'],
    url='https://rafael.herrerosolis.com',
    license='Apache License, Version 2.0',
    author='Rafael Herrero Solis',
    author_email='rafael@herrerosolis.com',
    description='Secure your django site settings',
    install_requires=[
        'pycrypto==2.6.1',
        'Django',
    ]
)
