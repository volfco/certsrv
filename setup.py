try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

config = {
    'description': 'A Python client for the Microsoft AD Certificate Services web page',
    'author': 'Colum McGaley',
    'url': 'https://github.com/volfco/certsrv',
    'download_url': 'https://github.com/volfco/certsrv',
    'version': '2.0.3',
    'py_modules': ['certsrv'],
    'name': 'certsrv',
	'console': ['certsrv.py'],
}

setup(**config)
