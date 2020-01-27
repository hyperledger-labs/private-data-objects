<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->
# Building the common libraries

Make sure you have environment variables `SGX_SDK`, `SGX_SSL` and `TINY_SCHEME_SRC` defined (see [environment.md](../docs/environment.md)) and then run
```
mkdir build
cd build
cmake .. -G "Unix Makefiles" && make
```
