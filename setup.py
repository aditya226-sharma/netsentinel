from setuptools import setup, find_packages

setup(
    name="netsentinel",
    version="1.0.0",
    description="Network Traffic Analysis & Security Monitoring Framework",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="NetSentinel Team",
    url="https://github.com/netsentinel/netsentinel",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "scapy>=2.5.0",
        "fastapi>=0.104.0",
        "uvicorn[standard]>=0.24.0",
        "typer[all]>=0.9.0",
        "rich>=13.7.0",
        "psutil>=5.9.0",
        "pyyaml>=6.0.1",
        "python-jose[cryptography]>=3.3.0",
        "passlib[bcrypt]>=1.7.4",
        "python-multipart>=0.0.6",
        "aiofiles>=23.2.1",
        "jinja2>=3.1.2",
        "pyjwt>=2.8.0",
        "weasyprint>=60.10",
    ],
    extras_require={
        "dev": [
            "pytest>=7.4.0",
            "pytest-asyncio>=0.21.0",
            "httpx>=0.25.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "netsentinel=cli:main",
        ],
    },
    include_package_data=True,
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Topic :: System :: Networking :: Monitoring",
        "Topic :: Security",
    ],
)
