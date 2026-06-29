from setuptools import setup, find_packages

setup(
    packages=find_packages(),
    include_package_data=True,
    entry_points={
        'console_scripts': [
            'ps1p=ps1p.cli:main',
        ],
    },
)
