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

# TODO WIP: Refactor classes


# Default file paths
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
            warnings.warn('No crypto key found, using: {}'.format(self.crypto_key))  # TODO: Remove this warning

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


# class HiddenSettings(EncryptedStoredSettings):
#     def __init__(self, hidden_settings_path=DEFAULT_HIDDEN_SETTINGS):
#         self.config_file_path = hidden_settings_path
#         super(HiddenSettings, self).__init__()


class DjangoDatabaseSettings(EncryptedStoredSettings):

    def database(self, alias, test=False):
        # TODO: Refactor
        return get_database(alias, path=self.config_file_path,
                            cryptokey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), test=test)


def python3_decode_utf8(text):
    if six.PY3:
        text = text.decode('utf-8')
    return text


def gen_aes_key(block_size=32):
    warnings.warn('DEPRECATED: use AESCipher().crypto_key instead')
    key = os.urandom(block_size)
    return binascii.hexlify(key)


def create_key_file(path):
    """
    Creates a key file
    :param path: Path to store the file
    :return:
    """
    warnings.warn('Deprecated function, use CryptoKeyFileManager instead')
    check_or_create_dir(os.path.dirname(path))
    os.chmod(os.path.dirname(path), stat.S_IRWXU)
    cryptokey = gen_aes_key()

    with open(path, b'w') as key_file:
        if six.PY3:
            key_file.write(cryptokey.decode('utf-8'))
        else:
            key_file.write(cryptokey)
        os.chmod(path, stat.S_IRUSR + stat.S_IWRITE)
    return cryptokey


def create_database_config_file(database, path=None, cryptokey=None, test=None):
    """
    Creates a database config file, all data will be encrypted
    :param database: Identifier for the database connection
    :param path: (optional) Path to the file that will store the database connection
    :param cryptokey: :param cryptokey: (Optional) Cryptographic key, WARNING: This should not be stored in your script,
    if you are not sure leave the defaullt value
    :param test: Used for tests
    :return:
    """

    database = database.replace('default', 'default_db')
    config = configparser.ConfigParser()
    if path is None:
        cfg_path = DEFAULT_DATABASES_CONF
    else:
        cfg_path = path
    check_or_create_dir(os.path.dirname(cfg_path))
    config.read(cfg_path)

    if database not in config.sections():
        config.add_section('{}'.format(database))
        if test is None:
            config.set(database, 'ENGINE', encrypt(
                DATABASE_ENGINES[prompt('Database engine (options: postgres, mysql, sqlite, oracle)')], hexkey=cryptokey))
            config.set(database, 'NAME', encrypt(prompt('Database name'), hexkey=cryptokey))
            config.set(database, 'USER', encrypt(prompt('Database user'), hexkey=cryptokey))
            config.set(database, 'PASSWORD', encrypt(password_prompt(), hexkey=cryptokey))
            config.set(database, 'HOST', encrypt(prompt('Database host'), hexkey=cryptokey))
            config.set(database, 'PORT', encrypt(prompt('Database port'), hexkey=cryptokey))
        else:
            config.set(database, 'ENGINE', encrypt(
                DATABASE_ENGINES['postgres'], hexkey=cryptokey))
            config.set(database, 'NAME', encrypt('test_db_name', hexkey=cryptokey))
            config.set(database, 'USER', encrypt('test_user', hexkey=cryptokey))
            config.set(database, 'PASSWORD', encrypt('test_password', hexkey=cryptokey))
            config.set(database, 'HOST', encrypt('test_host', hexkey=cryptokey))
            config.set(database, 'PORT', encrypt('5432', hexkey=cryptokey))

        with open(cfg_path, b'w') as cfgfile:
            config.write(cfgfile)


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


def read_key_file(path):
    """
    :param path:
    :return:
    """
    try:
        with open(path, b'r') as secret_file:
            cryptokey = secret_file.read().strip()

    except IOError:

        print("Cryptokey not found in {crpath}, creating random key".format(crpath=path))
        cryptokey = create_key_file(path)
    return cryptokey


def get_database(database_alias, path=None, cryptokey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), test=None):
    """
    Returns a database config
    :param database_alias: Config file section
    :param path: Config file path
    :param cryptokey: ...
    :param test: Used for tests
    :return: dict(Database config)
    """

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
            dbconfig[option.upper()] = decrypt(config.get(database_alias, option), hexkey=cryptokey)
        return dbconfig
    else:
        create_database_config_file(database_alias.replace('default_db', 'default'), path=cfg_path, cryptokey=cryptokey, test=test)

        return get_database(database_alias.replace('default_db', 'default'), path=cfg_path, cryptokey=cryptokey)


def encrypt(pwd, hexkey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), padchar='%', block_size=32):
    """
    Encrypt pwd
    :param pwd:
    :param hexkey:
    :param padchar:
    :param block_size:
    :return:
    """
    key = binascii.unhexlify(hexkey)
    pad = lambda s: s + (block_size - len(s) % block_size) * padchar
    EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))
    cipher = AES.new(key)
    encoded = EncodeAES(cipher, pwd)
    if six.PY3:
        encoded = encoded.decode('utf-8')
    return encoded


def decrypt(cyphertext, hexkey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), padchar=b'%'):
    """
    Decrypt encrypted text
    :param cyphertext: Encrypted text
    :param hexkey: Hexadecimal key used to encrypt the text.
    :param padchar: Padding character
    :return: Decrypted text (None if error)
    """
    try:
        key = binascii.unhexlify(hexkey)
    except TypeError:
        return None

    DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(padchar)
    key = key
    cipher = AES.new(key)

    try:
        decoded = DecodeAES(cipher, cyphertext)
    except TypeError:
        return None

    if six.PY3:
        decoded = decoded.decode('utf-8')

    return decoded


def get_secret_key(secret_file_path, cryptokey=read_key_file(DEFAULT_CRYPTO_KEY_FILE)):

    # logger.info("Reading existing key from: {path}".format(path=secret_file_path))
    path = os.path.dirname(secret_file_path)
    if not path:
        path = '.'
    check_or_create_dir(path)
    try:
        key = open(secret_file_path).read().strip()
    except IOError:

        key = ''.join(
                [random.SystemRandom().choice("{}{}{}".format(string.ascii_letters, string.digits, string.punctuation))
                 for i in range(50)])
        try:
            key = encrypt(key, hexkey=cryptokey)

            with open(secret_file_path, 'w') as secret:
                secret.write(key)
                os.chmod(secret_file_path, stat.S_IRUSR)

                # logger.info("Saving new SECRET_KEY to: {path}".format(path=secret_file_path))

        except IOError:
            # logger.error("Secret key file (%s) could not be created. "
            #              "Please create the file with the following secret key: "
            #              "\n %s \n or review file permissions!" % (secret_file_path, encrypt(key)))
            print("Secret key file (%s) could not be created. "
                  "Please create the file with the following secret key: "
                  "\n %s \n or review file permissions!" % (secret_file_path, encrypt(key)))
            return None
    return decrypt(key, cryptokey)


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


def get_s3_config(section, option, path=None, cryptokey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), prompt_funct=prompt):
    """
    Returns S3 bucket access info
    :param section: configparser section (str)
    :param option: configparser option (str)
    :param path: configuration file path
    :param cryptokey: (Optional) Cryptographic key, WARNING: This should not be stored in your script,
     if you are not sure leave the default value
    :param prompt_funct: (Optional) Function to retrieve password
    :return:
    """

    s3_basic_config = ['aws_bucket_name', 'S3_access_IAM_Key_Id', 'S3_access_IAM_Secret_Key']

    # TODO: Manage incomplete config files
    config = configparser.ConfigParser()
    if path is None:
        cfg_path = DEFAULT_HIDDEN_SETTINGS

    else:
        cfg_path = path
    config.read(cfg_path)

    # If section does not exist, create section
    if section not in config.sections():
        config.add_section('{}'.format(section))

        for option in s3_basic_config:
            config.set(section, option, encrypt(prompt_funct(option.replace('_', ' ')), hexkey=cryptokey))
            check_or_create_dir(os.path.dirname(cfg_path))

        with open(cfg_path, 'w') as cfgfile:
            config.write(cfgfile)
        config.read(cfg_path)

    try:
        return decrypt(config.get(section, option), cryptokey)
    except configparser.NoOptionError:
        config.set(section, option, encrypt(prompt_funct(option.replace('_', ' ')), hexkey=cryptokey))
        with open(cfg_path, 'w') as cfgfile:
            config.write(cfgfile)
        config.read(cfg_path)
        return get_s3_config(section, option, path=path, cryptokey=cryptokey)


def create_hidden_setting(section, option, config, config_file,
                          cryptokey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), test=None):
    """
    Prompts for a value for the [section] option value, saves it to the configuration file and returns
    :param section: configparser section (str)
    :param option: configparser option (str)
    :param config: configparser.ConfigParser() object
    :param config_file: path to configuration file
    :param cryptokey: (Optional) Cryptographic key, WARNING: This should not be stored in your script,
    if you are not sure leave the defaullt value
    :return: Encrypted value for [section] option at config_file
    :param test: Used for tests
    """
    if test is None:
        input_option = encrypt(prompt('[{0}] {1}'.format(section, option)), hexkey=cryptokey)
    else:
        input_option = encrypt(prompt('[{0}] {1}'.format(section, option), test_value=test), hexkey=cryptokey)
    check_or_create_dir(os.path.dirname(config_file))
    if section not in config.sections():
        config.add_section(section)

    config.set(section, option, input_option)
    with open(config_file, 'w') as cfgfile:
        config.write(cfgfile)
    return input_option


def hidden_setting(section, option, config_file=DEFAULT_HIDDEN_SETTINGS,
                   cryptokey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), test=None):
    """
    Get some sensible setting value, will prompt for it if it was not found on config_file
    :param section: configparser section (str)
    :param option: configparser option (str)
    :param config_file: (Optional) Configuration file were the encrypted settings are stored
    :param cryptokey: (Optional) Cryptographic key, WARNING: This should not be stored in your script,
     if you are not sure leave the default value
    :param test: Used for tests
    :return: Decrypted value for [section] option @ config_file
    """

    config = configparser.ConfigParser()
    config.read(config_file)

    try:
        setting = decrypt(config.get(section, option), hexkey=cryptokey)
    except (configparser.NoSectionError, configparser.NoOptionError):
        return decrypt(create_hidden_setting(section, option, config=config, config_file=config_file, cryptokey=cryptokey,
                                             test=test),
                       hexkey=cryptokey)
    return setting
