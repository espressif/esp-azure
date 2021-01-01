# RIoT Reference Architecture
## Introduction
Robust, Resilient, Recoverable Internet of Things (RIoT), from Microsoft Research, is an architecture for providing foundational trust services to computing devices. Device Identity Composition Engine ([DICE](https://trustedcomputinggroup.org/work-groups/dice-architectures/)) is an industry hardware/firmware standard that is the foundation on which RIoT is built.

This repository contains a RIoT reference implementation for a DICE Architecture that provides cryptographically strong device identity and device attestation.  Together, DICE and RIoT also provide a foundation for device recovery and resiliency ([Cyber Resilient Platform Initiative](https://aka.ms/cyres)), secure and verifiable updates, data at rest protection (sealing), and a host of other security-critical use cases.

The Device Provisioning Service (DPS) from Azure IoT uses DICE and RIoT for secure device identity and attestation.  The DPS X.509-based protocols rely on the cryptographic keys and certificates produced by RIoT and the Root of Trust for Measurement (RTM) provided by DICE in hardware.

For more info on DPS from Azure IoT [this](https://docs.microsoft.com/en-us/azure/iot-dps/) is a good place to start.

## The RIoT Repo
The RIoT repository is organized as follows:
 * _Reference_ -  A software emulator for DICE/RIoT.  The reference code can be used by developers to simulate inputs to DICE hardware and create DICE/RIoT keys and certificates based on those inputs.  The emulator is useful during dev/test to provide user-controlled inputs in a more developer-friendly environment.  The DICE/RIoT reference enables a much faster development cycle than working only with real hardware. 
 * _Simulation_ - A simulated DICE/RIoT-based MCU software stack.  The RIoT reference presents a simulated DICE device, the RIoT reference code itself, and very simple device firmware layer.  These three self-contained elements represent the basic components of a simple DICE-based MCU.  
 * _Pkgs_ - The packages directory contains the metadata and source code for supporting DICE/RIoT development in other languages.  In addition to the C-language reference, DICE/RIoT emulators and tests are also provided in Java (Maven), C# (NuGet), and javascript (npm).
 * _Tools_ - Sources, tools and tests enabling RIoT development and validation.

## Contributing
For more information on DICE, and to learn how you can contribute, we encourage you to check out the [DICE Workgroup](https://trustedcomputinggroup.org/work-groups/dice-architectures/) in the [Trusted Computing Group](https://trustedcomputinggroup.org/).  For questions, comments, or contributions to the RIoT project from MSR, feel free to contact us at riotdev@microsoft.com.

## Privacy & Cookies
https://go.microsoft.com/fwlink/?LinkId=521839

