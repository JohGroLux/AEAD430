# Lightweight Authenticated Encryption for 16-bit MSP430 Microcontrollers

The U.S. National Institute of Standards and Technology ([NIST](https://www.nist.gov)) is currently undertaking a process to evaluate and [standardize lightweight cryptographic algorithms](https://csrc.nist.gov/Projects/lightweight-cryptography) that are suitable for use in constrained environments where the performance of existing cryptographic standards is not sufficient. An example of such constrained environments are battery-powered [IoT](https://en.wikipedia.org/wiki/Internet_of_things) devices like wireless sensor nodes, which are typically equipped with a small 8, 16, or 32-bit microcontroller and possess only a few kB of RAM. The NIST considers two kinds of lightweight cryptosystems for standardization, namely algorithms for Authenticated Encryption with Associated Data ([AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption)) and hash functions. Similar to other NIST standardization activities, the Lightweight Cryptography (LWC) project involves an open process for proposing candidates together with a thorough multi-round evaluation to select the preferred one(s). This evaluation is now in the final round, which started in April 2021 and is expected to continue until (roughly) the first quarter of 2023. The 10 candidates that made it into the [final round](https://csrc.nist.gov/News/2021/lightweight-crypto-finalists-announced) are ASCON, Elephant, GIFT-COFB, Grain-128AEAD, ISAP, PHOTON-Beetle, Romulus, Sparkle, TinyJAMBU, and Xoodyak.

The evaluation of the 10 finalists takes into account both security aspects and the efficiency of implementations in hardware and software. Since there is no single dominating microcontroller platform in the IoT, it makes sense to assess the software performance of the finalists on a wide variety of 8, 16, and 32-bit architectures. For most candidates a number of implementations for 8 and 32-bit microcontrollers exist (most notably AVR and ARM), which were provided by the designers or independent third-party developers. These implementations were benchmarked by the NIST LWC team and detailed results regarding their execution time and code size are available on [GitHub](https://github.com/usnistgov/Lightweight-Cryptography-Benchmarking). However, to date, there exist no detailed benchmarking results for 16-bit platforms, simply due to the lack of suitable implementations (ideally with hand-written Assembler code for performance-critical components) for a 16-bit architecture. The purpose of this repository is to fill this gap by providing optimized implementations of the 10 finalists for the popular [16-bit MSP430](https://en.wikipedia.org/wiki/TI_MSP430) family of low-power microcontrollers.

This repository contains carefully-optimized MSP430 Assembler code for the most performance-critical building block of each of the ten final-round candidates. Many of the finalists are very efficient in software (as confirmed by the NIST benchmarking results) and outperform AES-GCM, the current "de-facto" standard for authenticated encryption. The most performance-critical component of these candidates is the underlying primitive, which is either a permutation (ASCON, Elephant, ISAP, PHOTON-Beetle, Sparkle, TinyJambu, Xoodyak), a block cipher (GIFT-COFB, Romulus) or a stream cipher (Grain-128AEAD). However, the implementations are not purely optimized for high speed but aim for a good trade-off between performance and (binary) code size. The assembler code is based on the syntax of [IAR Embedded Workbench for MSP430](https://www.iar.com/products/architectures/iar-embedded-workbench-for-msp430/), which differs slightly from the syntax of GCC. As shown in the table below, most of the ten components are very compact and have a code size of around 1 kB. The execution times were determined through cycle-accurate simulation using an MSP430F1611 as target device. On average, the Assembler implementation is twice as fast as the corresponding C code when it is compiled with medium optimization.

| AEAD Algorithm   | Assembler Component            | Execution time | Binary code size |
| :--------------: | :----------------------------: | :------------: | :--------------: |
| ASCON128         | P6 (6 rounds)                  | 3520 cycles    | 710 bytes        |
| Elephant (Dumbo) | Spongent-π[160] (80 rounds)    | cycles         | bytes            |
| Grain-128AEAD    | Pre-output generator (16 bits) | 589 cycles     | 916 bytes        |
| ISAP             | P6 (6 rounds)                  | 3520 cycles    | 710 bytes        |
| GIFT-COFB        | GIFT-128 (FS, 40 rounds)       | 3839 cycles    | 1144 bytes       |
| PHOTON-Beetle    | PHOTON256 (12 rounds)          | cycles         | bytes            | 
| Romulus-N        | Skinny-128-384+ (40 rounds)    | cycles         | bytes            |
| Schwaemm256-128  | SPARKLE384 (7 steps)           | 5958 cycles    | 640 bytes        |
| TinyJAMBU-128 v2 | P1024 (1024 steps)             | 2465 cycles    | 654 bytes        |
| Xoodyak          | Xoodoo (12 rounds)             | 8996 cycles    | 572 bytes        |
