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


# TODO: Config files permissions
# TODO: doble colon at s3 & celery
# TODO: Refactor classes


class Logger(object):
    # TODO: Mocked logger replace with logger.getLogger()
    def error(self, message):
        print(message)

    def info(self, message):
        print(message)

    def debug(self, message):
        print(message)

    def warning(self, message):
        print(message)


logger = Logger()

# Default file paths
DEFAULT_CRYPTO_KEY_FILE = os.path.expanduser('~/.private/django_secure.key')
DEFAULT_DATABASES_CONF = os.path.expanduser('~/.private/django_databases.cnf')
DEFAULT_HIDDEN_SETTINGS = os.path.expanduser('~/.private/django_secure_hidden_settings.cnf')


DATABASE_ENGINES = {
    'postgres': 'django.db.backends.postgresql',
    'mysql': 'django.db.backends.mysql',
    'sqlite': 'django.db.backends.sqlite3',
    'oracle': 'django.db.backends.oracle',
}


def gen_aes_key(block_size=32):
    """
    from djangosecure.cryptolib import gen_aes_key
    gen_aes_key()
    :param block_size:
    :return:
    """
    warnings.warn("shouldn't use this function anymore! Now use AESCipher.gen_aes_key.", DeprecationWarning)
    key = os.urandom(block_size)
    return binascii.hexlify(key)


def create_key_file(path):
    """
    Creates a key file
    :param path: Path to store the file
    :return:
    """
    check_or_create_dir(os.path.dirname(path))
    os.chmod(os.path.dirname(path), stat.S_IRWXU)
    cryptokey = gen_aes_key()

    with open(path, 'w') as key_file:
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

        with open(cfg_path, 'w') as cfgfile:
            config.write(cfgfile)


def password_prompt(message='database password'):
    pass1 = 0
    pass2 = 1
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
        with open(path, 'r') as secret_file:
            cryptokey = secret_file.read().strip()

    except IOError:

        print("Cryptokey not found in {crpath}, creating random key".format(crpath=path))
        cryptokey = create_key_file(path)
    return cryptokey


def get_database(database, path=None, cryptokey=read_key_file(DEFAULT_CRYPTO_KEY_FILE), test=None):
    """
    Returns a database config
    :param database: Config file section
    :param path: Config file path
    :param cryptokey: ...
    :param test: Used for tests
    :return: dict(Database config)
    """

    database = database.replace('default', 'default_db')
    config = configparser.ConfigParser()
    if path is None:
        cfg_path = DEFAULT_DATABASES_CONF
    else:
        cfg_path = path
    config.read(cfg_path)

    if database in config.sections():
        dbconfig = {}
        options = config.options(database)
        for option in options:
            dbconfig[option.upper()] = decrypt(config.get(database, option), hexkey=cryptokey)
        return dbconfig
    else:
        create_database_config_file(database.replace('default_db', 'default'), path=cfg_path, cryptokey=cryptokey, test=test)

        return get_database(database.replace('default_db', 'default'), path=cfg_path, cryptokey=cryptokey)


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
    :param message:
    :param test_value: Used for tests
    :return:
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


class EncryptedStoredSettings(object):
    def __init__(self, crypto_key_file=DEFAULT_CRYPTO_KEY_FILE, config_file=DEFAULT_HIDDEN_SETTINGS, test_mode=False):
        self.crypto_key = CryptoKeyFileManager(crypto_key_file).key # TODO: This goes in Cipher
        self.config_file_path = config_file
        self.test_mode = test_mode
        self.config_reader = configparser.ConfigParser()
        self.encrypted_config = self.read_encrypted_config()

    def get(self, section, option):

        try:
            setting = decrypt(self.encrypted_config.get(section, option), hexkey=self.crypto_key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return decrypt(
                create_hidden_setting(section, option, config=self.encrypted_config, config_file=self.config_file_path, cryptokey=self.crypto_key,
                                      test=self.test_mode),
                hexkey=self.crypto_key)
        return setting

    def save(self, section, option, value):
        raise NotImplementedError('WIP')

    def encrypt(self):
        raise NotImplementedError('WIP')

    def decrypt(self):
        raise NotImplementedError('WIP')

    def prompt(self, message, test_value=None):
        """
        Deal with python2 python3 input differences and use hidden input field for password like inputs
        :param message:
        :param test_value: Used for tests
        :return:
        """
        if test_value:
            return test_value

        passfields = ['S3 access IAM Secret Key', 'database password']
        if message in passfields or 'assword' in message:
            return password_prompt('%s: ' % message)
        else:
            return input('%s: ' % message)

    def read_encrypted_config(self):
        return self.config_reader.read(self.config_file_path)


class HiddenSettings(EncryptedStoredSettings):
    pass

    # def __init__(self, *args, **kwargs):
    #     super(HiddenSettings, self).__init__(*args, **kwargs)
    #     def


class CryptoKeyFileManager(object):
    """
    Usage:
        from djangosecure import CryptoKeyFileManager
        crypto_key = CryptoKeyFileManager('crypto/key/path.txt').key
    """
    block_size = 32

    def __init__(self, crypto_key_path):
        self.path = crypto_key_path

        try:
            self.key = self.read_key_file()
        except IOError:
            self.key = self.create_key_file()

    def read_key_file(self):
        with open(self.path, b'r') as crypto_key_file:
            return crypto_key_file.read().strip()

    def create_key_file(self):
        check_or_create_dir(os.path.dirname(self.path))
        os.chmod(os.path.dirname(self.path), stat.S_IRWXU)
        return self.write_key_file(gen_aes_key(block_size=self.block_size))

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


class Cipher(object):
    def __init__(self, crypto_key_file_path=DEFAULT_CRYPTO_KEY_FILE):
        self.crypto_key_file_path = crypto_key_file_path
        self.key_manager = CryptoKeyFileManager
        self.crypto_key = self.get_crypto_key()


    def get_crypto_key(self):
        return CryptoKeyFileManager(self.crypto_key_file_path).key

    def encrypt(self, plain_text):
        raise NotImplementedError('Must be defined at subclass')

    def decrypt(self, ciphered_text):
        raise NotImplementedError('Must be defined at subclass')

    def gen_key(self, *args, **kwargs):
        raise NotImplementedError('Must be defined at subclass')


class AESCipher(Cipher):
    block_size = 32
    padchar = '%'
    # TODO: Warning if pad char is found at the end of the string

    def encrypt(self, plain_text):
        key = binascii.unhexlify(self.crypto_key)  # TODO: from class
        pad = lambda s: s + (self.block_size - len(s) % self.block_size) * self.padchar  # TODO: Pad with self.pad
        EncodeAES = lambda c, s: base64.b64encode(c.encrypt(pad(s)))  # TODO: self.encode_aes()
        cipher = AES.new(key)  # TODO: To Class
        encoded = EncodeAES(cipher, plain_text)
        if six.PY3:
            encoded = encoded.decode('utf-8')
        return encoded

    def dencrypt(self, ciphered_text):
        key = self.unhexlify_crypto_key()

        DecodeAES = lambda c, e: c.decrypt(base64.b64decode(e)).rstrip(self.padchar)
        key = key
        cipher = AES.new(key)

        try:
            decoded = DecodeAES(cipher, ciphered_text)
        except TypeError:
            return None

        if six.PY3:
            decoded = decoded.decode('utf-8')

        return decoded

    def pad(self, text):
        characters_to_append = ((self.block_size - len(text)) % self.block_size)
        return text + characters_to_append * self.padchar

    def unhexlify_crypto_key(self):
        try:
            key = binascii.unhexlify(self.crypto_key)
        except TypeError:
            return None