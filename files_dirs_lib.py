# -*-coding: utf-8 -*-
import os
from django.utils.translation import ugettext as _


def check_or_create_dir(directorio, logger=None):
    """
    Check if some path exists, creating it if not
    :param directorio:
    :param logger: logging logger instance
    :return: True si existe o lo crea, False si hay errores
    """
    # TODO: Modificar para que en lugar de un bucle use un parametro tipo: mkdir -p
    path_existsts = os.path.isdir(directorio)


    if not path_existsts:
        try:
            os.makedirs(directorio)

            if logger:
                logger.info(_('Created directory: ') + directorio)
            else:
                print(_('Created directory: ') + directorio)
        except IOError:
            if logger:
                logger.info(_('Error creating directory: ') + directorio + _(' Check user permissions'))
            else:
                print(_('Error creating directory: ') + directorio + _(' Check user permissions'))
            return False
    return True