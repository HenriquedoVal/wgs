import os
from setuptools import setup, Extension

setup(
    name='wgs',
    ext_modules=[
        Extension(
            'wgs', ['main.c'],
            libraries=["build\\fnmatch", "zlib", "libcrypto_static"],

            define_macros=[
                # ("LOG_LEVEL", "LOG_ERROR"),
                ("PYTHON_BINDING", None)
            ],

            language="c",

            extra_link_args=["-nodefaultlib:libcmt"],
        )
    ]
)
