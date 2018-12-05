""" A setuptools based setup module. """


from setuptools import setup, find_packages
from codecs import open
from os import path

here = path.abspath(path.dirname(__file__))

# Get the long description from the README file
with open(path.join(here, 'README.md'), encoding='utf-8') as f:
    long_description = f.read()


setup(
    # This is the name of your project. 
    name='coconut-lib',  # Required

    # Versions.
    version='1.3.1',  # Required

    # One-line description.
    description='Threshold Issuance Selective Disclosure Credentials.',  # Required

    # Longer description,
    long_description=long_description,  # Optional

    # Denotes that the long_description is in Markdown.
    long_description_content_type='text/markdown',  # Optional

    # Link to the project's main homepage.
    url='https://pypi.org/project/coconut-lib',  # Optional

    # Author of the project.
    author='Alberto Sonnino',  # Optional

    # Email address corresponding to the author listed above.
    author_email='alberto.sonnino@ucl.ac.uk',  # Optional

    # Classifiers help users find your project by categorizing it.
    # For a list of valid classifiers, see https://pypi.org/classifiers/
    classifiers=[  # Optional
        # How mature is this project? Common values are
        #   3 - Alpha
        #   4 - Beta
        #   5 - Production/Stable
        'Development Status :: 4 - Beta',

        # Indicate who your project is intended for
        'Intended Audience :: Science/Research',
        'Topic :: Security :: Cryptography',

        # License as you wish
        'License :: OSI Approved :: BSD License',

        # Specify the Python versions are supported.
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3.5',
    ],

    # This field adds keywords to the project which will appear on the
    # project page.
    #
    # Note that this is a string of words separated by whitespace, not a list.
    keywords='anonymous-credentials threshold-cryptography blockchains distributed-ledgers',  # Optional

    # You can just specify package directories manually here if your project is
    # simple. Or you can use find_packages().
    #
    # Alternatively, if you just want to distribute a single Python file, use
    # the `py_modules` argument instead as follows, which will expect a file
    # called `my_module.py` to exist:
    #
    #   py_modules=["my_module"],
    #
    packages=find_packages(exclude=['contrib', 'docs', 'tests']),  # Required

    # This field lists other packages that the project depends on to run.
    # Any package put here will be installed by pip when the project is
    # installed, so they must be valid existing projects.
    #
    # For an analysis of "install_requires" vs pip's requirements files see:
    # https://packaging.python.org/en/latest/requirements.html
    install_requires=['petlib', 'bplib'],  # Optional

    # List additional groups of dependencies here (e.g. development
    # dependencies). Users will be able to install these using the "extras"
    # syntax, for example:
    #
    #   $ pip install sampleproject[dev]
    #
    # Similar to `install_requires` above, these must be valid existing
    # projects.
    ##extras_require={  # Optional
    ##    'dev': ['check-manifest'],
    ##    'test': ['coverage'],
    ##},

    # If there are data files included in your packages that need to be
    # installed, specify them here.
    #
    # If using Python 2.6 or earlier, then these have to be included in
    # MANIFEST.in as well.
    ##package_data={  # Optional
    ##    'sample': ['package_data.dat'],
    ##},

    # Although 'package_data' is the preferred approach, in some case you may
    # need to place data files outside of your packages. See:
    # http://docs.python.org/3.4/distutils/setupscript.html#installing-additional-files
    #
    # In this case, 'data_file' will be installed into '<sys.prefix>/my_data'
    ##data_files=[('my_data', ['data/data_file'])],  # Optional

    # To provide executable scripts, use entry points in preference to the
    # "scripts" keyword. Entry points provide cross-platform support and allow
    # `pip` to create the appropriate form of executable for the target
    # platform.
    #
    # For example, the following would provide a command called `sample` which
    # executes the function `main` from this package when invoked:
    ##entry_points={  # Optional
    ##    'console_scripts': [
    ##        'sample=sample:main',
    ##    ],
    ##},

    # List additional URLs that are relevant to your project as a dict.
    #
    # This field corresponds to the "Project-URL" metadata fields:
    # https://packaging.python.org/specifications/core-metadata/#project-url-multiple-use
    #
    # Examples listed include a pattern for specifying where the package tracks
    # issues, where the source is hosted, where to say thanks to the package
    # maintainers, and where to support the project financially. The key is
    # what's used to render the link text on PyPI.
    project_urls={  # Optional
        'Paper' : 'https://arxiv.org/abs/1802.07344',
        'Bug Reports': 'https://github.com/asonnino/coconut',
        'Funding': 'https://www.decodeproject.eu',
        'Source': 'https://github.com/asonnino/coconut',
    },
)
