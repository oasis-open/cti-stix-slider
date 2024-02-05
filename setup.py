# Standard Library
from os.path import abspath, dirname, join

# external
from setuptools import find_packages, setup

CUR_DIR = dirname(abspath(__file__))
INIT_FILE = join(CUR_DIR, 'stix2slider', 'cli.py')
VERSION_FILE = join(CUR_DIR, 'stix2slider', 'version.py')


def get_version():
    with open(VERSION_FILE) as f:
        for line in f:
            if not line.startswith("__version__"):
                continue

            version = line.split()[-1].strip('"')
            return version

        raise AttributeError("Package does not have a __version__")


def get_long_description():
    with open('README.rst') as f:
        return f.read()


setup(
    name='stix2-slider',
    version=get_version(),
    description='Utilities to downgrade STIX 2.1 content to STIX 1.X and CyBOX 2.1',
    long_description=get_long_description(),
    long_description_content_type='text/x-rst',
    url='https://oasis-open.github.io/cti-documentation/',
    author='OASIS Cyber Threat Intelligence Technical Committee',
    author_email='cti-users@lists.oasis-open.org',
    packages=find_packages(exclude=['*.test', '*.test.*']),
    install_requires=[
        'mixbox=1.0.5',
        'setuptools',
        'stix>=1.1.1.9,<=1.2.1.0',
        'stix-validator>=2.5.0',
        'stixmarx>=1.0.8',
        'stix2>=3.0.0',
    ],
    entry_points={
        'console_scripts': [
            'stix2_slider = stix2slider.cli:main',
        ],
    },
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: BSD License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12'
    ],
    keywords='stix stix2 json xml cti cyber threat intelligence',
    project_urls={
        'Documentation': 'https://cti-stix-slider.readthedocs.io/',
        'Source Code': 'https://github.com/oasis-open/cti-stix-slider/',
        'Bug Tracker': 'https://github.com/oasis-open/cti-stix-slider/issues/',
    },
)
