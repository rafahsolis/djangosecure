# from __future__ import unicode_literals
import six
import os
import djangosecure
from unittest import TestCase
from djangosecure.cryptolib import (
    CryptoKeyFileManager,
    EncryptedStoredSettings,
    DjangoDatabaseSettings,
)

# TODO: Increase tests coverage
# nosetests --with-coverage --cover-html
# nosetests --with-coverage --cover-html --cover-inclusive --cover-package=djangosecure


class DjangoSecureTestCase(TestCase):
    to_remove = []
    output_dir = None
    files = None

    @classmethod
    def setUpClass(cls):
        if six.PY3:
            cls.output_dir = 'tests/python3/'
        else:
            cls.output_dir = 'tests/python2/'
        cls.files = {
            'cryptokeyfile': os.path.join(cls.output_dir, 'criptokey.key'),
            'new_cryptokey': os.path.join(cls.output_dir, 'new_criptokey.key'),
            'keyfile': os.path.join(cls.output_dir, 'secret_key.secure'),
            'db_path': os.path.join(cls.output_dir, 'databases.cnf'),
            'S3_CFG': os.path.join(cls.output_dir, 'S3.cnf'),
            'hidden_settings': os.path.join(cls.output_dir, 'hidden.cnf'),
        }
        cls.cryptokey = djangosecure.cryptolib.read_key_file(cls.files['cryptokeyfile'])


class TestImportTestCase(DjangoSecureTestCase):

    def test_databases(self):
        database = {
            'default': djangosecure.get_database('production', path=self.files['db_path'], cryptokey=self.cryptokey,
                                                 test=True),
        }
        self.assertIsInstance(database, dict)
        self.assertEqual(database['default']['PORT'], '5432')

    def test_encrypt_decrypt(self):
        self.assertEqual('text', djangosecure.cryptolib.decrypt(djangosecure.cryptolib.encrypt('text')))

    def test_hidden_setting(self):
        # TODO: DEPRECATE hidde_setting function in favour of HiddenSettingReader()
        self.assertEqual(djangosecure.hidden_setting(
            'section', 'option', config_file=self.files['hidden_settings'], test='some_value'), 'some_value')

    def test_get_secret_key(self):
        key = djangosecure.get_secret_key(self.files['keyfile'], cryptokey=self.cryptokey)
        self.assertIsInstance(key, six.string_types)

    @classmethod
    def tearDownClass(cls):
        for file_dec, path in cls.files.items():
            try:
                os.remove(path)
            except OSError:
                pass
        os.removedirs(cls.output_dir)


class TestCriptolib(DjangoSecureTestCase):

    def setUp(self):
        self.cryptokey = CryptoKeyFileManager(self.files['cryptokeyfile'])
        self.hidden_settings = EncryptedStoredSettings(self.files['hidden_settings'],
                                                       crypto_key_file=self.files['cryptokeyfile'])
        self.database_settings = DjangoDatabaseSettings(self.files['db_path'])

    def test_crypto_key_file_manager(self):
        self.assertEqual(len(self.cryptokey.key), 64)

    def test_read_key_file(self):
        djangosecure.fileslib.check_or_create_dir(os.path.dirname(self.files['keyfile']))
        with open(self.files['cryptokeyfile'], b'w') as key_file:
            key_file.write('c8f12b2936034ee019fa1760dd6a4ce7065ead9b00cd20b48af0e408e89a9a02')
        self.assertEqual(djangosecure.cryptolib.CryptoKeyFileManager(self.files['cryptokeyfile']).key,
                         'c8f12b2936034ee019fa1760dd6a4ce7065ead9b00cd20b48af0e408e89a9a02')

    def test_hidden_settings(self):
        # Set value
        self.assertEqual('test setting value', self.hidden_settings.get('test_section', 'test_option',
                                                                        test_value='test setting value'))
        # Recover value
        self.assertEqual('test setting value', self.hidden_settings.get('test_section', 'test_option'))

    def test_create_key_file(self):
        new_cryptokey = CryptoKeyFileManager(self.files['new_cryptokey'])
        self.assertTrue(os.path.isfile(new_cryptokey.path))
    # @classmethod
    # def tearDownClass(cls):
    #     for file_dec, path in cls.files.items():
    #         try:
    #             os.remove(path)
    #         except OSError:
    #             pass
    #     os.removedirs(cls.output_dir)

    def test_get_database(self):
        database = self.database_settings.database('default', test=True)
        self.assertDictEqual(database, {
            'ENGINE': 'django.db.backends.postgresql',
            'NAME': 'test_db_name',
            'USER': 'test_user',
            'PASSWORD': 'test_password',
            'HOST': 'test_host',
            'PORT': '5432',
        })
