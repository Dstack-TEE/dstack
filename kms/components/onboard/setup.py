from setuptools import setup, find_packages

setup(
    name="dstack-kms-onboard",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "fastapi>=0.105.0",
        "uvicorn>=0.24.0",
        "jinja2>=3.1.2",
        "requests>=2.31.0",
        "python-multipart>=0.0.6",
        "cryptography>=44.0.0",
    ],
    python_requires=">=3.8",
)
