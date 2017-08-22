#!/usr/bin/env python

from setuptools import setup

setup(name="stravaweblib",
      version="0.0.1",
      description="Extends the Strava v3 API using web scraping",
      url="https://github.com/pR0Ps/stravaweblib",
      license="MPLv2",
      classifiers=[
          "Programming Language :: Python :: 3",
          "Programming Language :: Python :: 3.3",
          "Programming Language :: Python :: 3.4",
          "Programming Language :: Python :: 3.5",
          "Programming Language :: Python :: 3.6",
      ],
      packages=["stravaweblib"],
      install_requires=["stravalib>=0.6.6,<1.0.0", "beautifulsoup4>=4.6.0,<5.0.0"]
)
