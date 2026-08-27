from setuptools import setup
import sys
import shutil
import os

setup(
    name="edgeguard-sdk",
    version="0.2.0",
    description="Sub-microsecond on-device AI guardrails engine for local LLMs and Edge AI",
    author="EdgeGuard Team",
    py_modules=["edgeguard"],
    install_requires=[
        "pyyaml>=6.0",
    ],
    include_package_data=True,
    classifiers=[
        "Programming Language :: Python :: 3",
        "Programming Language :: Rust",
        "Topic :: Security",
        "Topic :: Scientific/Engineering :: Artificial Intelligence",
    ],
    python_requires=">=3.8",
)
