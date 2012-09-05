#!/usr/bin/env python
from distribute_setup import use_setuptools
use_setuptools()

from setuptools import setup
import re
import platform
import os
import sys


def load_version(filename='yara/version.py'):
    """Parse a __version__ number from a source file"""
    with open(filename) as source:
        text = source.read()
        match = re.search(r"^__version__ = ['\"]([^'\"]*)['\"]", text)
        if not match:
            msg = "Unable to find version number in {}".format(filename)
            raise RuntimeError(msg)
        version = match.group(1)
        return version


#build the yara package data (shipped yar files)
yara_package_data = []
for path, _, files in os.walk(os.path.join('yara', 'rules')):
    rootpath = path[len('yara') + 1:]
    for f in files:
        if f.endswith('.yar'):
            yara_package_data.append(os.path.join(rootpath, f))


#see if we have a pre-built libyara for this platform
arch, exetype = platform.architecture()
libs = []
libspath = os.path.join('.', 'libs', exetype, arch)
if os.path.exists(libspath):
    for lib in filter(lambda x: os.path.splitext(x)[-1] in ['.so', '.dll'],
            os.listdir(libspath)):
        libs.append(os.path.join(libspath, lib))
data_files = []
if libs:
    if exetype == 'ELF':
        libdir = os.path.join(sys.prefix, 'lib')
    else:
        libdir = os.path.join(sys.prefix, 'DLLs')
    data_files.append((libdir, libs))
else:
    print("WARNING: No libs found at %s" % libspath)
    print("You need to 'make install' libyara (yara-1.6) for this platform")

setup(
    name="yara",
    version=load_version(),
    packages=['yara'],
    package_data=dict(yara=yara_package_data),
    data_files=data_files,
    zip_safe=False,
    author="Michael Dorman",
    author_email="mjdorma@gmail.com",
    url="http://code.google.com/p/yara-project/",
    description="Compile YARA rules to test against files or strings",
    long_description=open('README.rst').read(),
    license="Apache Software Licence",
    install_requires = [],
    platforms=['cygwin', 'win', 'linux'],
    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Other Audience',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: Microsoft :: Windows',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.2',
        'Programming Language :: Python :: 3.3',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Security',
        'Topic :: System :: Monitoring'
    ],
    test_suite="tests"
)
