import setuptools

with open('README.md', 'r') as fh:
    long_description = fh.read()

setuptools.setup(
    name='nrfsec',
    version='0.1.7',
    python_requires='>=3.5',
    entry_points={
        "console_scripts": ['nrfsec = nrfsec.nrfsec:main']
        },
    author='BuildXYZ',
    author_email='buildxyz@gmail.com',
    description='An embedded security research tool for unlocking and reading memory from Nordic nRF51 SoCs',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/buildxyz-git/nrfsec',

    packages=setuptools.find_packages(),

    classifiers=[
        'Programming Language :: Python :: 3',
        'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
        'Operating System :: OS Independent',
        'Natural Language :: English',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3',
        'Topic :: Software Development :: Embedded Systems'
     ],

    install_requires=[
        'pyswd',
        'tabulate',
        'tqdm',
        'argparse',
        'coloredlogs'
    ],
 )