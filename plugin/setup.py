from setuptools import setup

setup(
    name="octoprint-bambu",
    version="0.5.0",
    description="OctoPrint plugin for Bambu Lab printers over LAN MQTT with TLS pinning",
    author="OctoBambu",
    license="AGPLv3",
    packages=["octoprint_bambu"],
    include_package_data=True,
    python_requires=">=3.9",
    install_requires=["OctoPrint>=1.10.0", "paho-mqtt>=2.0.0"],
    entry_points={"octoprint.plugin": ["bambu = octoprint_bambu:BambuPlugin"]},
)
