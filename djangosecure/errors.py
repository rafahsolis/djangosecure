# -*-coding: utf-8 -*-

class ImproperlyConfiguredError(Exception):
    """ Improperly Configured Exception """
    def __init__(self, *args):
        super(ImproperlyConfiguredError, self).__init__(*args)