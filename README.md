rocc-template
=============
Note - Compatible with rocket-chip:master (Commit ID 4234cff0744bae1f602b84011dbef261584c0a27)

If cloned into rocket-chip directory use

    ./install-symlinks

You can then test it using the emulator

    cd ../emulator && make CONFIG=AesDefaultConfig run-asm-tests

You can emulate the software implementation of rsa by running

    ./emulator-Top-AesDefaultConfig pk ../rsa/tests/rsa-sw.rv +dramsim

or

    ./emulator-Top-AesDefaultConfig pk ../rsa/tests/rsa-sw-bm.rv +dramsim

You can emulate the accelerated rsa by running

    ./emulator-Top-AesDefaultConfig pk ../rsa/tests/rsa-rocc-bm.rv +dramsim

or 

    ./emulator-Top-AesDefaultConfig pk ../rsa/tests/rsa-rocc.rv +dramsim

The -bm versions of the code omit the print statements and will complete faster.
