# -*-coding: utf-8 -*-

import os
import stat
import logging
try:
    # Python2.7
    import ConfigParser as configparser  # pragma: no cover
except ImportError:  # pragma: no cover
    # Python3
    import configparser  # pragma: no cover

import base64
import binascii
import getpass
import random
import string
from Crypto.Cipher import AES
from django.conf import settings
from files_dirs_lib import check_or_create_dir

logger = logging.getLogger('utils.cryptolib')


DATABASE_ENGINES = {
    'postgres': 'django.db.backends.postgresql',
    'mysql': 'django.db.backends.mysql',
    'sqlite': 'django.db.backends.sqlite3',
    'oracle': 'django.db.backends.oracle',
}


def gen_aes_key(block_size=32):
    """

    :param block_size:
    :return:
    """
    # [random.SystemRandom().choice("{}{}{}".format(string.ascii_letters, string.digits, string.punctuation)) for i in range(block_size)])
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
        key_file.write(cryptokey)
        os.chmod(path, stat.S_IRUSR + stat.S_IWRITE)
    return cryptokey


"""
TODO: Modify with optional database connection to be able to test.
move prompts to separated function
"""
def create_database_config_file(database, path=None, cryptokey=None):  # pragma: no cover
    """
    Creates a database config file, all data will be encrypted
    :param database: Identifier for the database connection
    :param path: (optional) Path to the file that will store the database connection
    """
    database = database.replace('default', 'default_db')  # pragma: no cover
    config = configparser.ConfigParser()  # pragma: no cover
    if path is None:  # pragma: no cover
        cfg_path = os.path.join(settings.PROJECT_DIR, 'databases.cnf')  # pragma: no cover
    else:  # pragma: no cover
        cfg_path = path  # pragma: no cover
    config.read(cfg_path)  # pragma: no cover

    if database not in config.sections():  # pragma: no cover
        # TODO: Refactor to support python3 input()
        config.add_section('{}'.format(database))  # pragma: no cover
        config.set(database, 'ENGINE', encrypt(DATABASE_ENGINES[raw_input('Database engine (options: postgres, mysql, sqlite, oracle): ')], hexkey=cryptokey))  # pragma: no cover
        config.set(database, 'NAME', encrypt(raw_input('Database name: '), hexkey=cryptokey))  # pragma: no cover
        config.set(database, 'USER', encrypt(raw_input('Database user: '), hexkey=cryptokey))  # pragma: no cover
        config.set(database, 'PASSWORD', encrypt(password_prompt(), hexkey=cryptokey))  # pragma: no cover
        config.set(database, 'HOST', encrypt(raw_input('Database host: '), hexkey=cryptokey))  # pragma: no cover
        config.set(database, 'PORT', encrypt(raw_input('Database port: '), hexkey=cryptokey))  # pragma: no cover

        with open(cfg_path, 'w') as cfgfile:  # pragma: no cover
            config.write(cfgfile)  # pragma: no cover


def password_prompt(message='database password'):  # pragma: no cover
    pass1 = 0  # pragma: no cover
    pass2 = 1  # pragma: no cover
    while pass1 != pass2:  # pragma: no cover
        pass1 = getpass.getpass('Enter {message}: '.format(message=message))  # pragma: no cover
        pass2 = getpass.getpass('Confirm {message}: '.format(message=message))  # pragma: no cover

        if pass1 != pass2:  # pragma: no cover
            print("\nPasswords don't match, try again...\n")  # pragma: no cover
    return pass1  # pragma: no cover


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


def get_database(database, path=None, cryptokey=read_key_file(os.path.expanduser('~/.private/cpc.key'))):
    """
    Returns a database config
    :param database: Config file section
    :param path: Config file path
    :param cryptokey: ...
    :return: dict(Database config)
    """
    # if settings.TESTING:
    #     path = settings.TESTS_DATABASE_CFG

    database = database.replace('default', 'default_db')
    config = configparser.ConfigParser()
    if path is None:
        raise NotImplementedError('Criptolib.get_database: fix path generation')
        # cfg_path = os.path.join(settings.PROJECT_DIR, 'databases.cnf')
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
        create_database_config_file(database.replace('default_db', 'default'), path=path, cryptokey=cryptokey)  # pragma: no cover
        return get_database(database.replace('default_db', 'default'), path=path)  # pragma: no cover


def encrypt(pwd, hexkey=read_key_file(os.path.expanduser('~/.private/cpc.key')), padchar='%', block_size=32):
    """

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
    return encoded


def decrypt(cyphertext, hexkey=read_key_file(os.path.expanduser('~/.private/cpc.key')), padchar='%'):
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
        logger.error("Error decodig '{ct}'".format(ct=cyphertext))
        return None

    return decoded


def get_secret_key(secret_file_path):
    try:
        key = decrypt(open(secret_file_path).read().strip())
    except IOError:

        key = ''.join(
                [random.SystemRandom().choice("{}{}{}".format(string.ascii_letters, string.digits, string.punctuation))
                 for i in range(50)])
        try:
            with open(secret_file_path, 'w') as secret:
                secret.write(encrypt(key))

        except IOError:
            logger.error("Secret key file (%s) could not be created. "
                         "Please create the file with the following secret key: "
                         "\n %s \n or review file permissions!" % (secret_file_path, encrypt(key)))
            return None
    return key


# def get_s3_config(section, option, path=None, cryptokey=read_key_file(os.path.expanduser('~/.private/cpc.key'))):
#     """
#     Returns S3 bucket access info
#     :param section: config section
#     :param part:
#     :param cryptokey:
#     :param path:
#     :return:
#     """
#     logger.warning('Using deprecated cpc_core.utils.cryptolib.get_s3_config, '
#                    'use cpc_core.utils.cryptolib.get_s3_config_new instead')
#
#     config = configparser.ConfigParser()
#     if path is None:
#         raise NotImplementedError("Fix generate s3conf path cryptolib.get_s3_config")  # pragma: no cover
#         # cfg_path = os.path.join(settings.PROJECT_DIR, 's3.cnf')
#     else:
#         cfg_path = path
#     config.read(cfg_path)
#     if section not in config.sections():
#         config.add_section('{}'.format(section))
#         config.set(section, 'S3_access_IAM_Key_Id', encrypt(raw_input('S3 access IAM Key: ')))
#         config.set(section, 'S3_access_IAM_Secret_Key', encrypt(password_prompt('S3 access IAM Secret Key')))
#         with open(cfg_path, 'a') as cfgfile:
#             config.write(cfgfile)
#         config.read(cfg_path)
#
#         # try:
#     return decrypt(config.get(section, option), cryptokey)
    # except configparser.NoOptionError:
    #     if option == 'S3_access_IAM_Secret_Key':
    #         config.set(section, option, encrypt(password_prompt('S3 access IAM Secret Key')))
    #     else:
    #         config.set(section, 'S3_access_IAM_Key_Id', encrypt(raw_input('S3 access IAM Key: ')))
    #     with open(cfg_path, 'a') as cfgfile:
    #         config.write(cfgfile)
    #     config.read(cfg_path)
    #     return decrypt(config.get(section, option), cryptokey)


def prompt(message):
    """
    Deal with python2 python3 input differences and use hidden input field for password like inputs
    :param message:
    :return:
    """
    passfields = ['S3 access IAM Secret Key', 'database password']  # pragma: no cover
    if message in passfields:  # pragma: no cover
        return password_prompt('%s: ' % message)  # pragma: no cover
    else:  # pragma: no cover
        try:  # pragma: no cover
            return raw_input('%s: ' % message)  # pragma: no cover
        except NameError:  # pragma: no cover
            return input('%s: ' % message)  # pragma: no cover


def get_s3_config_new(section, option, path=None, cryptokey=read_key_file(os.path.expanduser('~/.private/cpc.key')), prompt_funct=prompt):
    """
    Returns S3 bucket access info
    :param section: config section
    :param option:
    :param cryptokey:
    :param path:
    :return:
    """
    s3_basic_config = ['aws_bucket_name', 'S3_access_IAM_Key_Id', 'S3_access_IAM_Secret_Key']

    # TODO: Manage incomplete config files
    config = configparser.ConfigParser()
    if path is None:
        raise NotImplementedError("Fix generate s3conf path cryptolib.get_s3_config")
        # cfg_path = os.path.join(settings.PROJECT_DIR, 's3.cnf')
    else:
        cfg_path = path
    config.read(cfg_path)

    # If section does not exist, create whole section
    if section not in config.sections():
        config.add_section('{}'.format(section))
        for option in s3_basic_config:
            config.set(section, option, encrypt(prompt_funct(option.replace('_', ' ')), hexkey=cryptokey))

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
        return get_s3_config_new(section, option, path=path, cryptokey=cryptokey)



