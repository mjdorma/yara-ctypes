from setuptools import setup

import re
import platform
import os
import sys

if 'test' in sys.argv:
    # Setup test unloads modules after the tests have completed. This causes an
    # error in atexit's exit calls because the registered modules no longer
    # exist.  This hack resolves this issue by disabling the register func
    import atexit
    atexit.register = lambda be_gone_nasty_traceback: True

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
system = platform.system().lower()
machine = platform.machine().lower()

if machine in ['i686', 'x86']:
    machine = 'x86_32'

if machine in ['amd64']:
    machine = 'x86_64'

if system == 'windows':
    ext = '.dll'
else:
    ext = '.so'

libyara_path = os.path.join('.', 'libs', system, machine, "libyara" + ext)
data_files = []
if os.path.exists(libyara_path):
    if system == 'windows':
        install_libdir = os.path.join(sys.prefix, 'DLLs')
    else:
        install_libdir = os.path.join(sys.prefix, 'lib')
    data_files.append((install_libdir, [libyara_path]))

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
    entry_points={
        'console_scripts': [
            'yara-ctypes = yara.cli:entry'
            ]
    },
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

if not data_files:
    print("\nWARNING: Could not find %s" % libyara_path)
    print("You need to 'make install' libyara for this system/machine")
    print("See http://pythonhosted.org/yara/ for help")


