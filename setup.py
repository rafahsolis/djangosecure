from distutils.core import setup

setup(
    name='djangosecure',
    version='0.0.0',
    packages=['djangosecure'],
    url='https://rafael.herrerosolis.com',
    license='Apache License, Version 2.0',
    author='Rafael Herrero Solis',
    author_email='rafael@herrerosolis.com',
    description='Secure your django site settings',
    install_requires=['pycrypto==2.6.1']
)
