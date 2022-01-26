# Publish to pip cheat-sheet:
#
#    1. Commit, Tag
#    2. git push, git push --tags
#    3. rm dist/*
#    4. python3 setup.py sdist
#    5. python3 setup.py bdist_wheel
#    6. twine upload dist/*
#
import setuptools
from distutils.core import setup

from passcrow import VERSION

setup(
  name = 'passcrow',
  packages = ['passcrow', 'passcrow.handlers', 'passcrow.integration'],
  entry_points = {'console_scripts': ['passcrow=passcrow.__main__:main']},
  version = VERSION,
  license='LGPL-3.0',
  description = "passcrow",
  long_description = """\
Passcrow is a system for implementing secure "password escrow", making it
possible to recover from forgetting or losing a key, password or passphrase.

The user experience should be similar to the "reset password" recovery
flow of popular online services, but adapted to the needs of Open Source,
decentralization and users keeping locally encrypted data.
""",
  author = 'Bjarni R. Einarsson',
  author_email = 'bre@mailpile.is',
  url = 'https://github.com/mailpile/python-passcrow',
  download_url = 'https://codeload.github.com/mailpile/python-passcrow/tar.gz/refs/tags/v'+VERSION,
  keywords = ['passcrow', 'encryption', 'password', 'passphrase', 'escrow'],
  install_requires=[],
  classifiers=[
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU Lesser General Public License v3 or later (LGPLv3+)',
    'Programming Language :: Python :: 3',
    'Programming Language :: Python :: Implementation :: CPython',
    'Topic :: Internet',
    'Topic :: Security :: Cryptography',
    'Topic :: Software Development :: Libraries :: Python Modules'])
