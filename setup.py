from setuptools import setup, find_packages

setup(
    name="edgeguard",
    version="0.2.0",
    packages=find_packages(),
    package_data={"edgeguard": ["*.dylib", "*.so", "*.dll", "*.yaml"]},
    include_package_data=True,
    install_requires=["pyyaml>=6.0"],
)
