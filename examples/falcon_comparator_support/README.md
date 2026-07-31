# Falcon comparator support

`deterministic_randombytes.c` is a CT-KAT-owned, non-cryptographic interposer
used only by structural and deterministic transcript probes. It replaces OS
entropy so repeated Valgrind runs analyze the same valid key and signing
randomness. It is excluded from physical timing and production builds.
