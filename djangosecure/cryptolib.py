# -*-coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import os
import stat
import six
import warnings
from builtins import input
# import logging
# try:
#     # Python2.7
#     import ConfigParser as configparser
# except ImportError:
#     # Python3
#     import configparser
from configparser import ConfigParser, NoOptionError, NoSectionError
import base64
import binascii
import getpass
import random
import string
from Crypto.Cipher import AES
from io import open
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
            decoded = self.cipher.decrypt(base64.b64decode(ciphered_text))
        except TypeError:
            return None
        return python3_decode_utf8(decoded).rstrip(self.pad_char)

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


"""
from djangosecure.cryptolib import CryptoKeyFileManager
a = CryptoKeyFileManager('/root/rm.me')
"""
class CryptoKeyFileManager(object):

    CipherClass = AESCipher

    def __init__(self, crypto_key_path):
        self.path = crypto_key_path
        try:
            self.key = self.read_key_file()
        except IOError:
            self.key = self.create_key_file()
        if self.key is None:
            self.key = self.create_key_file()

        self.cipher = self.CipherClass(self.key)

    def read_key_file(self):
        with open(self.path, "r") as crypto_key_file:
            return crypto_key_file.read().strip()

    def create_key_file(self):
        check_or_create_dir(os.path.dirname(self.path))
        os.chmod(os.path.dirname(self.path), stat.S_IRWXU)
        return self.write_key_file(self.CipherClass().crypto_key)

    def write_key_file(self, crypto_key):
        with open(self.path, 'w') as key_file:
            if six.PY3:
                key_file.write(crypto_key.decode('utf-8'))
            else:
                key_file.write(crypto_key.decode('utf-8'))
            os.chmod(self.path, stat.S_IRUSR + stat.S_IWRITE)
        return crypto_key

    def __str__(self):
        return self.key


class EncryptedStoredSettings(object):

    def __init__(self, config_file_path, crypto_key_file=DEFAULT_CRYPTO_KEY_FILE,  test_mode=False):
        self.cipher_manager = CryptoKeyFileManager(crypto_key_file)
        self.config_file_path = config_file_path
        self.check_config_file_path_has_been_set()
        check_or_create_dir(os.path.dirname(self.config_file_path))
        self.test_mode = test_mode
        self.encrypted_config = ConfigParser()
        self.cipher = self.cipher_manager.cipher
        self.read_encrypted_config()

    def get(self, section, option, test_value=None):
        try:
            setting = self.encrypted_config.get(section, option)
            setting = self.cipher.decrypt(setting)
        except (NoSectionError, NoOptionError):
            setting = self.prompt(message="[{}] {}".format(section, option), test_value=test_value)
            self.save_encrypted_setting(section, option, setting)
        return setting

    def read_encrypted_config(self):
        return self.encrypted_config.read(self.config_file_path)

    def write_encrypted_config(self):
        with open(self.config_file_path, 'w') as cnf_file:
            self.encrypted_config.write(cnf_file)

    def check_or_create_section(self, section):
        if not self.encrypted_config.has_section(section):
            self.encrypted_config.add_section(section)

    def save_encrypted_setting(self, section, option, value):
        self.check_or_create_section(section)
        self.encrypted_config.set(section, option, self.cipher.encrypt(value))
        self.write_encrypted_config()

    def check_config_file_path_has_been_set(self):
        if self.config_file_path is None:
            raise ImproperlyConfiguredError("{} should define config_file_path attribute, where the encripted settings\n"
                                            "will be stored.".format(self.__class__.__name__))

    @staticmethod
    def prompt(message, test_value=None, hide=False):
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
    config = ConfigParser()
    alias = None
    alias_fixed = None

    def settings(self, alias, test=None):
        self.alias = alias

        self.alias_fixed = self.alias.replace('default', 'default_db')
        if six.PY2:
            self.alias_fixed = self.alias_fixed.decode('utf-8')
        self.create_alias_if_not_in_config()
        self.test = test
        return self.get_database()

    def create_alias_if_not_in_config(self):
        if self.alias_fixed not in self.config.sections():
            self.config.add_section('{}'.format(self.alias_fixed))

    def get_database(self):
        config = ConfigParser()
        if self.config_file_path is None:
            cfg_path = DEFAULT_DATABASES_CONF
        else:
            cfg_path = self.config_file_path
        config.read(cfg_path)

        if self.alias_fixed in config.sections():
            dbconfig = {}
            options = config.options(self.alias_fixed)
            for option in options:
                dbconfig[option.upper()] = self.cipher.decrypt(config.get(self.alias_fixed, option))
            return dbconfig
        else:
            self.create_database_config_file()

            return self.get_database()

    def create_database_config_file(self):

        if self.test is None:
            self.prompt_for_database_settings(self.config)
        else:
            self.set_test(self.config, self.alias)

        with open(self.config_file_path, 'w') as cfgfile:
            self.config.write(cfgfile)

    def prompt_for_database_settings(self, config):
        self.prompt_for_database_engine(config, self.alias)
        for setting_key in ['NAME', 'HOST', 'PORT', 'USER']:
            config.set(self.alias_fixed, setting_key, self.cipher.encrypt(prompt('Database {}'.format(setting_key))))
        config.set(self.alias_fixed, 'PASSWORD', self.cipher.encrypt(password_prompt()))

    def prompt_for_database_engine(self, config, alias):
        config.set(alias.replace('default', 'default_db'), 'ENGINE', self.cipher.encrypt(
            DATABASE_ENGINES[prompt('Database engine (options: postgres, mysql, sqlite, oracle)')]))

    def set_test(self, test, alias):
        if isinstance(test, dict):
            self.set_test_from_dict(test, alias)
        else:
            self.set_test_from_dict({
                'ENGINE': DATABASE_ENGINES['postgres'],
                'NAME': u'test_db_name',
                'USER': u'test_user',
                'PASSWORD': u'test_password',
                'HOST': u'test_host',
                'PORT': u'5432',
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
        pass1 = getpass.getpass('Enter {message}: '.format(message=message))
        pass2 = getpass.getpass('Confirm {message}: '.format(message=message))

        if pass1 != pass2:
            print("\nPasswords don't match, try again...\n")
    return pass1


def python3_decode_utf8(text):
    try:
        text = text.decode('utf-8')
    except AttributeError:
        pass
    return text


# def safe_unicode(text):
#     if isinstance(text, unicode):
#         return text
#     else:
#         return text.decode('utf-8')


class DjangoSecretKey(EncryptedStoredSettings):
    @property
    def key(self):
        try:
            return self.cipher.decrypt(open(self.config_file_path).read().strip())
        except IOError:
            return self.create_encripted_config()

    def read_encrypted_config(self):
        pass

    def create_encripted_config(self):
        key = self.generate_random_secret_key()
        with open(self.config_file_path, 'w') as secret:
            secret.write(python3_decode_utf8(self.cipher.encrypt(key)))
        return key

    @staticmethod
    def generate_random_secret_key():
        key = ''.join(
            [random.SystemRandom().choice("{}{}{}".format(string.ascii_letters, string.digits, string.punctuation))
             for i in range(50)])
        return key
