import setuptools

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setuptools.setup(
    name="crl-checker",
    version="0.0.1",
    author="Michal Sadowski",
    author_email="misad90@gmail.com",
    description="Check if certificate is revoked using the x509 CRL extension",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/fulder/crl-checker/",
    project_urls={
        "Bug Tracker": "https://github.com/fulder/crl-checker/issues",
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
    ],
    package_dir={"": "."},
    packages=setuptools.find_packages(),
    python_requires=">=3.9",
)