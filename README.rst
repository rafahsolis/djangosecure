djangosecure
============

|build status| |coverage report| Secure Django settings (Works with
other Python scripts)

This module creates a cryptokey outside the django project directory,
encrypts with that cryptokey your django sensible settings and stores
the encrypted values.

You can use it at your project settings.py file \* Note: Before running
the django site with gunicorn or similar for the first time, you must
run somme manage command to be prompt for the sensible settings \*
Developed for Linux/Python2.7, Python3.5

Install
=======

Linux required packages: python-dev (python3.5-dev if python==3.5)
libgmp-dev gcc ``pip install djangosecure``

Examples
========

SECRET\_KEY
-----------

settings.py

::

    from djangosecure import DjangoSecretKey


    SECRET_KEY_FILE_PATH = '/some/path/to/store/file.secret'
    secret_key = DjangoSecretKey(SECRET_KEY_FILE_PATH)
    SECRET_KEY = secret_key.key

-  Note: If the secret key file path does not exist it will try to
   create it. (write permissio required @SECRET\_KEY\_FILE\_PATH origin)
-  Note: The secret file will be automatically created the first time
   you call secret\_key.key
-  The cryptographic key is stored by default at
   ~/.private/django\_secure.key you can change this by passing
   crypto\_key\_file= to the DjangoSecretKey constructor:
   ``secret_key = DjangoSecretKey(SECRET_KEY_FILE_PATH, crypto_key_file='path/to/your/cryptokey')``
   DjangoDatabaseSettings and EncryptedStoredSettings accept
   crypto\_key\_file parameter too.

DATABASES
---------

The first time you run python manage.py runserver you will be prompted
for your database settings. They will be saved encrypted with the
generated cryptokey generated by django-secure module.

You can have as many database configurations, change the parameter to
change the configuration and running ``python manage.py runserver`` you
will be prompted again for the new settings

::

    from djangosecure import DjangoDatabaseSettings
    databases = DjangoDatabaseSettings(os.path.join(PROJECT_ROOT, 'databases.cnf'), crypto_key_file='path/to/your/cryptokey)

    DATABASES = {
        'default': 'default': databases.settings('production'),
    }

Other settings
--------------

To encrypt any other setting use EncryptedStoredSettings, for example:

::

    from djangosecure import EncryptedStoredSettings
    encripted_settings = EncryptedStoredSettings('./hidden/settings/path'))

    CELERY_BROKER = 'amqp://{0}:{1}@localhost//'.format(
        encripted_settings.get('celery', 'broker_username', config_file="config/file/path/here.cfg"),
        encripted_settings.get('celery', 'broker_password')
        )

Runing tests
============

nosetests --with-coverage --cover-html
======================================

nosetests --with-coverage --cover-html --cover-inclusive --cover-package=djangosecure
=====================================================================================

-  Note: File and path are automatically created at first call

.. |build status| image:: https://git.herrerosolis.com/rafahsolis/djangosecure/badges/master/build.svg
   :target: https://git.herrerosolis.com/rafahsolis/djangosecure/commits/master
.. |coverage report| image:: https://git.herrerosolis.com/rafahsolis/djangosecure/badges/master/coverage.svg
   :target: https://git.herrerosolis.com/rafahsolis/djangosecure/commits/master
