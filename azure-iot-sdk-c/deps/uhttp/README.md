# uhttp

The uhttp provides a platform independent http implementation via the Azure C SDKs.

## Dependencies

azure-uhttp-c depends on azure-c-shared.

azure-uhttp-c uses cmake for configuring build files.

## Setup

1. Clone **azure-uhttp-c** using the recursive option:

```
git clone --recursive https://github.com/Azure/azure-uhttp-c.git
```

2. Create a folder called *cmake* under *azure-uhttp-c

3. Switch to the *cmake* folder and run
```
cmake ..
```

4. Build

```
cmake --build .
```

### Installation and Use
Optionally, you may choose to install azure-c-shared-utility on your machine:

1. Switch to the *cmake* folder and run
    ```
    cmake -Duse_installed_dependencies=ON ../
    ```
    ```
    cmake --build . --target install
    ```

    or install using the follow commands for each platform:

    On Linux:
    ```
    sudo make install
    ```

2. Use it in your project (if installed)
    ```
    find_package(azure_uhttp_c REQUIRED CONFIG)
    target_link_library(yourlib uhttp)
    ```

_If running tests, this requires that umock-c, azure-ctest, and azure-c-testrunnerswitcher, azure-c-shared-utility
 are installed (through CMake) on your machine._

## Configuration options

In order to turn on/off the tlsio implementations use the following CMAKE options:

* `-Duse_custom_heap:bool={ON/OFF}` - turns disables/enables the implementations in `gballoc.c` and requires that an external library implement the `gballoc_malloc` family.
* `-Dno_logging:bool={ON/OFF}` - turns on/off logging
* `-Duse_openssl:bool={ON/OFF}` - turns on/off the OpenSSL support. If this option is use an environment variable name OpenSSLDir should be set to point to the OpenSSL folder.
* `-Dmemory_trace:bool={ON/OFF}` - turns on/off gballoc_xxx functions for memory alocation
* `-Duse_installed_dependencies:bool={ON/OFF}` - turns on/off building azure-c-shared-utility using installed dependencies. This package may only be installed if this flag is ON.
* `-Drun_unittests:bool={ON/OFF}` - enables building of unit tests. Default is OFF.

## Contributing

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
