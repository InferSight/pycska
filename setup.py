#!/usr/bin/env python

from distutils.core import setup

setup(
  name = 'pycska',
  packages = ['pycska'], # this must be the same as the name above
  version = '0.2',
  description = 'Infersight CSKA API',
  author = 'Steve Graham',
  author_email = 'sgraham@infersight.com',
  url = 'https://github.com/infersight/pycska',
  download_url = 'https://github.com/infersight/pycska/archive/0.2.tar.gz',
  keywords = ['infersight', 'cska'], # arbitrary keywords
  install_requires=[
          'requests==2.14.2',
          'requests-oauthlib==0.8.0',
          'sphinx_rtd_theme==0.2.5b1'
      ],
  classifiers = [],
)
