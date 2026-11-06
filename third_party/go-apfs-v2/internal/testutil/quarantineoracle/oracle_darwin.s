//go:build darwin && native_quarantine_oracle

#include "textflag.h"
TEXT captureTrampoline<>(SB),NOSPLIT,$0-0
 JMP captureNative(SB)
GLOBL ·captureAddress(SB), RODATA, $8
DATA ·captureAddress(SB)/8, $captureTrampoline<>(SB)
TEXT applyTrampoline<>(SB),NOSPLIT,$0-0
 JMP applyNative(SB)
GLOBL ·applyAddress(SB), RODATA, $8
DATA ·applyAddress(SB)/8, $applyTrampoline<>(SB)
