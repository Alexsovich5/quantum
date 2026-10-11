from setuptools import find_packages, setup

setup(
    name="quantum_tool",
    version="0.1.0",
    description="Scan TLS endpoints for quantum-vulnerable public-key cryptography",
    package_dir={"": "src"},
    packages=find_packages("src"),
    package_data={"quantum_tool": ["templates/*.j2"]},
    python_requires=">=3.8",
    install_requires=[
        "cryptography==2.9.2",
        "pyOpenSSL==19.1.0",
        "PyYAML==5.3.1",
        "Jinja2==2.11.2",
        "click==7.1.2",
    ],
    entry_points={"console_scripts": ["quantum=quantum_tool.cli:main"]},
)
