# -*-coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import os
import stat
import six
import warnings
from builtins import input
# import logging
try:
    # Python2.7
    import ConfigParser as configparser
except ImportError:
    # Python3
    import configparser

import base64
import binascii
import getpass
import random
import string
from Crypto.Cipher import AES
from .fileslib import check_or_create_dir
from djangosecure.errors import ImproperlyConfiguredError

DEFAULT_CRYPTO_KEY_FILE = os.path.expanduser('~/.private/django_secure.key')
DEFAULT_DATABASES_CONF = os.path.expanduser('~/.private/django_databases.cnf')
DEFAULT_HIDDEN_SETTINGS = os.path.expanduser('~/.private/django_secure_hidden_settings.cnf')
OTHER_PASSWORD_FIELDS = ['S3 access IAM Secret Key']


DATABASE_ENGINES = {
    'postgres': 'django.db.backends.postgresql',
    'mysql': 'django.db.backends.mysql',
    'sqlite': 'django.db.backends.sqlite3',
    'oracle': 'django.db.backends.oracle',
}


class Cipher(object):
    """ Base class to implement ciphers """
    def __init__(self, crypto_key=None):
        self.crypto_key = crypto_key
        self.check_crypto_key()

    def check_crypto_key(self):
        if self.crypto_key is None:
            self.crypto_key = self.gen_key()

    def encrypt(self, plain_text):
        raise NotImplementedError('Must be defined at subclass')

    def decrypt(self, ciphered_text):
        raise NotImplementedError('Must be defined at subclass')

    def gen_key(self, *args, **kwargs):
        raise NotImplementedError('Must be defined at subclass setting self.crypto_key value')


class AESCipher(Cipher):
    """
    from djangosecure.cryptolib import AESCipher
    c = AESCipher('sample/key.k')
    """
    block_size = 32
    pad_char = '%'

    def __init__(self, *args):
        super(AESCipher, self).__init__(*args)
        self.unhexlified_crypto_key = self.unhexlify_crypto_key()
        self.cipher = AES.new(self.unhexlified_crypto_key)

    def encrypt(self, plain_text):
        encoded = self.encode_aes(plain_text)
        return encoded

    def encode_aes(self, plain_text):
        if plain_text.endswith(self.pad_char):
            warnings.warn('Detected pad char at the end of text, will be lost.')
        encoded = base64.b64encode(self.cipher.encrypt(self.pad(plain_text)))
        return python3_decode_utf8(encoded)

    def decode_aes(self, ciphered_text):
        try:
            decoded = self.cipher.decrypt(base64.b64decode(ciphered_text)).rstrip(self.pad_char)
        except TypeError:
            return None
        return python3_decode_utf8(decoded)

    def decrypt(self, ciphered_text):
        try:
            decoded = self.decode_aes(ciphered_text)
        except TypeError:
            return None
        return python3_decode_utf8(decoded)

    def pad(self, text):
        characters_to_append = ((self.block_size - len(text)) % self.block_size)
        return text + characters_to_append * self.pad_char

    def unhexlify_crypto_key(self):
        try:
            return binascii.unhexlify(self.crypto_key)
        except TypeError:
            warnings.warn('Crypto Key could not be unhexlified')
            return None

    def gen_key(self, *args, **kwargs):
        key = os.urandom(self.block_size)
        return binascii.hexlify(key)


class CryptoKeyFileManager(object):
    """
    Usage:
        from djangosecure.cryptolib import CryptoKeyFileManager
        crypto_key = CryptoKeyFileManager('crypto/key/path.txt')
    """
    CipherClass = AESCipher

    def __init__(self, crypto_key_path):
        self.path = crypto_key_path
        try:
            self.key = self.read_key_file()
        except IOError:
            self.key = self.create_key_file()
        self.cipher = self.CipherClass(self.key)

    def read_key_file(self):
        with open(self.path, b'r') as crypto_key_file:
            return crypto_key_file.read().strip()

    def create_key_file(self):
        check_or_create_dir(os.path.dirname(self.path))
        os.chmod(os.path.dirname(self.path), stat.S_IRWXU)
        return self.write_key_file(self.CipherClass().crypto_key)

    def write_key_file(self, crypto_key):
        with open(self.path, b'w') as key_file:
            if six.PY3:
                key_file.write(crypto_key.decode('utf-8'))
            else:
                key_file.write(crypto_key)
            os.chmod(self.path, stat.S_IRUSR + stat.S_IWRITE)
        return crypto_key

    def __str__(self):
        return self.key


class EncryptedStoredSettings(object):

    def __init__(self, config_file_path, crypto_key_file=DEFAULT_CRYPTO_KEY_FILE,  test_mode=False):
        self.cipher_manager = CryptoKeyFileManager(crypto_key_file)
        self.config_file_path = config_file_path
        self.check_config_file_path_has_been_set()
        self.test_mode = test_mode
        self.encrypted_config = configparser.ConfigParser()
        self.read_encrypted_config()
        self.cipher = self.cipher_manager.cipher

    def get(self, section, option, test_value=None):
        try:
            setting = self.encrypted_config.get(section, option)
            setting = self.cipher.decrypt(setting)
        except (configparser.NoSectionError, configparser.NoOptionError):
            setting = self.prompt(message="[{}] {}".format(section, option), test_value=test_value)
            self.save_encrypted_setting(section, option, setting)
        return setting

    # def modify(self, section, option, test_value=None):
    #     raise NotImplementedError('Coming Soon')

    def read_encrypted_config(self):
        return self.encrypted_config.read(self.config_file_path)

    def write_encrypted_config(self):
        with open(self.config_file_path, b'w') as cnf_file:
            self.encrypted_config.write(cnf_file)

    def check_or_create_section(self, section):
        if not self.encrypted_config.has_section(section):
            self.encrypted_config.add_section(section)

    def save_encrypted_setting(self, section, option, value):
        # value = self.cipher.encrypt(value)
        self.check_or_create_section(section)
        self.encrypted_config.set(section, option, self.cipher.encrypt(value))
        self.write_encrypted_config()

    def check_config_file_path_has_been_set(self):
        if self.config_file_path is None:
            raise ImproperlyConfiguredError("{} should define config_file_path attribute, where the encripted settings\n"
                                            "will be stored.".format(
                self.__class__.__name__))

    def prompt(self, message, test_value=None, hide=False):
        """
        Deal with python2 python3 input differences and don't show what's typed for password like inputs
        """
        if test_value:
            return test_value

        if use_password_prompt(message) or hide:
            return password_prompt('%s: ' % message)
        else:
            return input('%s: ' % message)


def use_password_prompt(message):
    if 'assword' in message or message in OTHER_PASSWORD_FIELDS:
        return True
    return False


class DjangoDatabaseSettings(EncryptedStoredSettings):
    test = None
    config = configparser.ConfigParser()

    def database(self, alias, test=None):

        self.create_alias_if_not_in_config(alias)
        self.test = test
        return self.get_database(alias, path=self.config_file_path, test=test)

    def create_alias_if_not_in_config(self, alias):
        database = self.read_database_from_config(alias)

        if database not in self.config.sections():
            self.config.add_section('{}'.format(database))

    def get_database(self, database_alias, path=None, test=None):
        database_alias = database_alias.replace('default', 'default_db')
        config = configparser.ConfigParser()
        if path is None:
            cfg_path = DEFAULT_DATABASES_CONF
        else:
            cfg_path = path
        config.read(cfg_path)

        if database_alias in config.sections():
            dbconfig = {}
            options = config.options(database_alias)
            for option in options:
                dbconfig[option.upper()] = self.cipher.decrypt(config.get(database_alias, option))
            return dbconfig
        else:
            self.create_database_config_file(database_alias.replace('default_db', 'default'))

            return self.get_database(database_alias.replace('default_db', 'default'), path=cfg_path)

    def create_database_config_file(self, database):
        """
        Creates a database config file, all data will be encrypted
        :param database: Identifier for the database connection
        :param path: (optional) Path to the file that will store the database connection
        :param test: True/False; If true avoids prompt for settings
        :return:
        """

        if self.test is None:
            self.prompt_for_database_settings(self.config, database)
        else:
            self.set_test(self.config, database)

        with open(self.config_file_path, b'w') as cfgfile:
            self.config.write(cfgfile)

    def read_database_from_config(self, database):
        database = database.replace('default', 'default_db')
        if self.config_file_path is None:
            cfg_path = DEFAULT_DATABASES_CONF
        else:
            cfg_path = self.config_file_path

        check_or_create_dir(os.path.dirname(cfg_path))
        self.config.read(cfg_path)
        return database

    def prompt_for_database_settings(self, config, database):
        self.prompt_for_database_engine(config, database)
        for setting_key in ['NAME', 'HOST', 'PORT', 'USER']:
            config.set(database, setting_key, self.cipher.encrypt(prompt('Database {}'.format(setting_key))))
        config.set(database, 'PASSWORD', self.cipher.encrypt(password_prompt()))

    def prompt_for_database_engine(self, config, database):
        config.set(database, 'ENGINE', self.cipher.encrypt(
            DATABASE_ENGINES[prompt('Database engine (options: postgres, mysql, sqlite, oracle)')]))

    def set_test(self, test, alias):
        if isinstance(test, dict):
            self.set_test_from_dict(test, alias)
        else:
            self.set_test_from_dict({
                'ENGINE': DATABASE_ENGINES['postgres'],
                'NAME': 'test_db_name',
                'USER': 'test_user',
                'PASSWORD': 'test_password',
                'HOST': 'test_host',
                'PORT': '5432',
            }, alias)

    def set_test_from_dict(self, test, database_alias):
        for k, v in test.items():
            self.config.set(database_alias.replace('default', 'default_db'), k, self.cipher.encrypt(v))


def prompt(message, test_value=None):
    """
    Deal with python2 python3 input differences and use hidden input field for password like inputs
    """
    if test_value:
        return test_value

    passfields = ['S3 access IAM Secret Key', 'database password']
    if message in passfields or 'assword' in message:
        return password_prompt('%s: ' % message)
    else:
        return input('%s: ' % message)


def password_prompt(message='Password'):
    pass1 = 0
    pass2 = 1
    message.replace(' :', '')
    while pass1 != pass2:
        pass1 = getpass.getpass('Enter {message}'.format(message=message))
        pass2 = getpass.getpass('Confirm {message}'.format(message=message))

        if pass1 != pass2:
            print("\nPasswords don't match, try again...\n")
    return pass1


def python3_decode_utf8(text):
    if six.PY3:
        text = text.decode('utf-8')
    return text


class DjangoSecretKey(EncryptedStoredSettings):
    @property
    def key(self):
        try:
            key = self.cipher.decrypt(open(self.config_file_path).read().strip())
        except IOError:

            key = ''.join(
                    [random.SystemRandom().choice("{}{}{}".format(string.ascii_letters, string.digits, string.punctuation))
                     for i in range(50)])

            with open(self.config_file_path, b'w') as secret:
                secret.write(self.cipher.encrypt(key))
        return key
