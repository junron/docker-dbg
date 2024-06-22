from setuptools import setup, find_packages

setup(name='docker_dbg',
      version='0.2.0',
      description='Tools for debugging processes running in docker containers',
      author='jro',
      install_requires=[ "pwntools"],
      package_data={'docker_dbg': ['binaries/*']},
      package_dir={"": "src"},
      packages=find_packages(where="src"))