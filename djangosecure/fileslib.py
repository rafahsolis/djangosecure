# -*-coding: utf-8 -*-
from __future__ import absolute_import, unicode_literals
import os
# from django.utils.translation import ugettext as _


def check_or_create_dir(directorio, logger=None):
    """
    Check if some path exists, creating it if not
    :param directorio:
    :param logger: logging logger instance
    :return: True si existe o lo crea, False si hay errores
    """
    # TODO: Modificar para que en lugar de un bucle use un parametro tipo: mkdir -p

    if not directorio:
        return
    if not os.path.isdir(directorio):
        try:
            os.makedirs(directorio)

            if logger:
                logger.info('Created directory: ' + directorio)
            else:
                print('Created directory: ' + directorio)
        except IOError:
            if logger:
                logger.info('Error creating directory: ' + directorio + ' Check user permissions')
            else:
                print('Error creating directory: ' + directorio + ' Check user permissions')
            return False
    return True


def set_perms(path, perms):
    raise NotImplementedError('Not implemented yet')
