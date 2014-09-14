PwdLdLibrary
============

Dynamically load Windows password filters

## How To

* Compile this into a DLL and copy it to System32
* Add the necessary registry keys to configure this library. See the sample .reg file.
* Add "PwdLdLibrary" to `HKEY_LOCAL_MACHINE/SYSTEM/CurrentControlSet/Control/Lsa`

## Credit

* Thanks @brian-cole for migrating portions of this from C to C++ and fixing numerous bugs along the way.
