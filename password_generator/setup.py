from setuptools import setup, find_packages

setup(
    name="password-generator",
    version="1.0.0",
    description="Secure, random password generator with a rich CLI",
    long_description=open("README.md").read(),
    long_description_content_type="text/markdown",
    author="Your Name",
    author_email="your@email.com",
    url="https://github.com/yourusername/password-generator",
    license="MIT",
    py_modules=["password_generator", "cli"],
    python_requires=">=3.10",
    entry_points={
        "console_scripts": [
            "passgen=cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security",
        "Topic :: Utilities",
        "Environment :: Console",
    ],
    extras_require={
        "dev": ["pytest>=7.0", "pytest-cov"],
    },
)
