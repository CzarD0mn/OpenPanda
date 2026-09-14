from setuptools import setup

setup(
    name="octoprint-openpanda",
    version="0.6.0",
    description="OctoPrint plugin for Bambu Lab printers over LAN MQTT with TLS pinning before MQTT auth",
    author="OpenPanda",
    license="AGPLv3",
    packages=["octoprint_openpanda"],
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=["OctoPrint>=1.10.0", "paho-mqtt>=2.0.0"],
    entry_points={"octoprint.plugin": ["openpanda = octoprint_openpanda:OpenPandaPlugin"]},
)
