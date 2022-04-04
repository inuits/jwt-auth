from distutils.core import setup

setup(
    name='inuits_jwt_auth',
    version='0.0.24',
    description="A Wrapper for authlib library with roles and permissions",
    classifiers=[
        'License :: OSI Approved :: GNU General Public License v2 (GPLv2)',
        'Intended Audience :: Developers',
        'Programming Language :: Python :: 3'
    ],
    author='Matthias Dillen',
    author_email='matthias.dillen@inuits.eu',
    license='GPLv2',
    packages=[
        'inuits_jwt_auth'
    ],
    install_requires=[
        "requests>=2.25.0",
        "Authlib~=1.0.0b1",
        "Flask>=1.1.2",
        "Werkzeug>=1.0.1"

    ],
    provides=['inuits_jwt_auth']
)
