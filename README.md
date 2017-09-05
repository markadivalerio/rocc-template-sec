rocc-template
=============
Note - Compatible with rocket-chip:master (Commit ID 4234cff0744bae1f602b84011dbef261584c0a27)

If cloned into rocket-chip directory use

    ./install-symlinks

You can then test it using the emulator

    cd ../emulator && make CONFIG=AesDefaultConfig run-asm-tests

You can emulate the software implementation of aes by running

    ./emulator-Top-AesDefaultConfig pk ../aes/tests/aes-sw.rv +dramsim

or

    ./emulator-Top-AesDefaultConfig pk ../aes/tests/aes-sw-bm.rv +dramsim

You can emulate the accelerated aes by running

    ./emulator-Top-AesDefaultConfig pk ../aes/tests/aes-rocc-bm.rv +dramsim

or 

    ./emulator-Top-AesDefaultConfig pk ../aes/tests/aes-rocc.rv +dramsim

The -bm versions of the code omit the print statements and will complete faster.
