This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/). For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.

# Microsoft Azure MQTT

azure-umqtt-c is a general purpose library build for MQTT protocol

## Dependencies

azure-mqtt client use the azure-c-shared-utility, which is a C library provisioning common functionality for basic tasks (like string, list manipulation, IO, etc.).
azure-c-shared-utility is available here: <https://github.com/Azure/azure-c-shared-utility>.
azure-c-shared-utility needs to be built before building azure-mqtt-c.  

## Setup

### Build

- Clone azure-umqtt-c by:

```Shell
git clone https://github.com/Azure/azure-umqtt-c.git
cd azure-umqtt-c
git submodule update --init
```

- Create a folder cmake under azure-umqtt-c

- Switch to the cmake folder and run

```Shell
cmake ..
```

- Build

```Shell
cmake --build .
```

### Installation and Use

Optionally, you may choose to install azure-umqtt-c on your machine:

1. Switch to the *cmake* folder and run

    ```Shell
    cmake -Duse_installed=ON ../
    cmake --build . --target install
    ```

    or install using the follow commands for each platform:

    On Linux:

    ```Shell
    sudo make install
    ```

    On Windows:

    ```Shell
    find_package(umqtt REQUIRED CONFIG)
    target_link_library(yourlib umqtt)
    ```

_This requires that azure-c-shared-utility is installed (through CMake) on your machine._

_If running tests, this requires that umock-c, azure-ctest, and azure-c-testrunnerswitcher are installed (through CMake) on your machine._

### Building the tests

In order to build the tests use:

```Shell
cmake .. -Drun_unittests:bool=ON
```
