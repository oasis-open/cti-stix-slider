from os.path import abspath, dirname, join

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
    name="stix2-slider",
    version=get_version(),
    description="Utilities to downgrade STIX and CybOX content to 1.X",
    long_description=get_long_description(),
    url="http://stixproject.github.io/",
    author='OASIS Cyber Threat Intelligence Technical Committee',
    author_email='cti-users@lists.oasis-open.org',
    maintainer='Rich Piazza',
    maintainer_email='rpiazza@mitre.org',
    packages=find_packages(),
    install_requires=[
        'stix>=1.1.1.9,<1.2.1.0',
        'stix-validator>=2.5.0',
        'stixmarx>=1.0.6',
        'six>=1.10.0',
        'stix2>=1.3.1'
    ],
    entry_points={
        'console_scripts': [
            'stix2_slider = stix2slider.cli:main',
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Development Status :: 2 - Pre-Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ]
)
