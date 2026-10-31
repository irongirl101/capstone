from setuptools import find_packages, setup


setup(
    name="gov",
    version="0.1.0",
    description="Zero-trust AI governance prototype",
    package_dir={"": "src"},
    packages=find_packages("src"),
    python_requires=">=3.10",
    install_requires=["pydantic>=2.5", "pyyaml>=6"],
    extras_require={"dev": ["pytest>=8"], "proxy": ["mitmproxy>=10"]},
)
