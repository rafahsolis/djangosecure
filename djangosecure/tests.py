# from __future__ import unicode_literals
import six
import os
import djangosecure
from unittest import TestCase

# TODO: Increase tests coverage
# nosetests --with-coverage --cover-html
# nosetests --with-coverage --cover-html --cover-inclusive --cover-package=djangosecure


class TestImportTestCase(TestCase):
    @classmethod
    def setUpClass(cls):
        if six.PY3:
            cls.output_dir = 'tests/python3/'
        else:
            cls.output_dir = 'tests/python2/'
        cls.files = {
            'cryptokeyfile': os.path.join(cls.output_dir, 'criptokey.key'),
            'keyfile': os.path.join(cls.output_dir, 'secret_key.secure'),
            'db_path': os.path.join(cls.output_dir, 'databases.cnf'),
            'S3_CFG': os.path.join(cls.output_dir, 'S3.cnf'),
            'hidden_settings': os.path.join(cls.output_dir, 'hidden.cnf'),
        }
        cls.cryptokey = djangosecure.cryptolib.read_key_file(cls.files['cryptokeyfile'])

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

    # test S3 IAM Settings
    # AWS_STORAGE_BUCKET_NAME = 'bucket_name'
    # AWS_ACCESS_KEY_ID = djangosecure.get_s3_config(AWS_STORAGE_BUCKET_NAME, 'S3_access_IAM_Key_Id',
        # path=S3_CFG, cryptokey=cryptokey)
    # AWS_SECRET_ACCESS_KEY = djangosecure.get_s3_config(AWS_STORAGE_BUCKET_NAME, 'S3_access_IAM_Secret_Key',
        # path=S3_CFG, cryptokey=cryptokey)
    # print('S3 TEST:', AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
    #
    # # test Hidden setting
    # from djangosecure import hidden_setting
    # CELERY_BROKER = 'amqp://{0}:{1}@localhost//'.format(
    #     hidden_setting('celery', 'broker_username', config_file=hidden_settings, cryptokey=cryptokey),
    #     hidden_setting('celery', 'broker_password', config_file=hidden_settings, cryptokey=cryptokey)
    #     )
    # print('HIDDEN SETTING TEST:', CELERY_BROKER)
