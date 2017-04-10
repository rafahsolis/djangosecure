import os
from setuptools import setup

# from distutils.core import setup

# allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))


def here(name):
    return os.path.join(
        os.path.dirname(os.path.abspath(__file__)),
        name)


def read(name, mode='rb', encoding='utf8'):
    os.system('pandoc --from=markdown --to=rst --output=README.rst README.md')
    if os.path.exists('README.rst'):
        long_description = open('README.rst').read()
    else:
        with open(here(name), mode) as fp:
            long_description = fp.read().decode(encoding)
    return long_description

# Development Status :: 1 - Planning
# Development Status :: 2 - Pre-Alpha
# Development Status :: 3 - Alpha
# Development Status :: 4 - Beta
# Development Status :: 5 - Production/Stable
# Development Status :: 6 - Mature
# Development Status :: 7 - Inactive

setup(
    name='djangosecure',
    version='v0.0.3',
    packages=['djangosecure'],
    url='https://github.com/rafahsolis/djangosecure',
    download_url='https://github.com/rafahsolis/djangosecure/tarball/v0.0.3',
    license='Apache License, Version 2.0',
    author='Rafael Herrero Solis',
    author_email='rafael@herrerosolis.com',
    keywords=['django', 'secure', 'settings'],
    description='Secure your django sensible settings',
    long_description=read('README.md'),
    test_suite='nose.collector',
    tests_require=['nose', 'six'],
    install_requires=[
        'pycrypto==2.6.1',
        'Django',
        'six==1.10.0',
        'future==0.16.0',
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],
)
