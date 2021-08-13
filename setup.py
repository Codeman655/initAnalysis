#!/usr/bin/env python
# Install with python setup.py (develop|install)

from setuptools import setup, find_packages
long_description = ""
console_scripts = ['initAnalysis=initAnalysis:main']

setup(name='initAnalysis',
      version='0.1.0',
      description="Graphing and Static Recon tool for Linux's SystemV",
      long_description=long_description,
      long_description_content_type="text/markdown",
      author='craigca',
      author_email='craigca@ornl.gov',
      url='https://nowhere.com', #this should probably be code-int
      packages=find_packages(),
      entry_points = {'console_scripts': console_scripts},
      install_requires=[ 'binwalk==2.1.0',
        'decorator==4.4.2',
        'networkx==2.5.1',
        'pkg-resources==0.0.0',
        'pygraphviz==1.6',
        'python-magic==0.4.22'],
      python_requires='>=3.6',
     )

