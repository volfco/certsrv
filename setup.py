try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

import py2exe

from glob import glob

config = {
    'description': 'A Python client for the Microsoft AD Certificate Services web page',
    'author': 'Magnus Watn',
    'url': 'https://github.com/volfco/certsrv',
    'download_url': 'https://github.com/volfco/certsrv',
    'version': '0.9',
    'py_modules': ['certsrv'],
    'name': 'certsrv',
	'console': ['certsrv.py'],
	'data_files': [("Microsoft.VC140.CRT", glob(r'C:\Program Files (x86)\Microsoft Visual Studio 14.0\VC\redist\x86\Microsoft.VC140.CRT\*.*'))]
}

setup(**config)
