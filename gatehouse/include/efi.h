// SPDX-License-Identifier: GPL-2.0-or-later
// Copyright (C) 2026 HackintARM contributors

/*
 * gatehouse/include/efi.h
 *
 * Minimal, self-contained UEFI definitions. No EDK2 / gnu-efi dependency.
 * Only the subset Gatehouse actually touches is declared, but the
 * EFI_BOOT_SERVICES table is laid out in full order so that member offsets
 * match the firmware's real table.
 */
#ifndef GATEHOUSE_EFI_H
#define GATEHOUSE_EFI_H

typedef unsigned char      UINT8;
typedef unsigned short     UINT16;
typedef unsigned int       UINT32;
typedef unsigned long long UINT64;
typedef signed long long   INT64;
typedef unsigned long long UINTN;
typedef signed long long   INTN;
typedef unsigned char      BOOLEAN;
typedef unsigned short     CHAR16;
typedef char               CHAR8;
typedef void               VOID;

typedef VOID        *EFI_HANDLE;
typedef UINTN        EFI_STATUS;
typedef UINT64       EFI_PHYSICAL_ADDRESS;
typedef UINT64       EFI_VIRTUAL_ADDRESS;

#define EFIAPI
#define IN
#define OUT
#define OPTIONAL

#define EFI_SUCCESS          ((EFI_STATUS)0)
#define EFI_LOAD_ERROR       ((EFI_STATUS)1)
#define EFI_INVALID_PARAMETER ((EFI_STATUS)2)
#define EFI_UNSUPPORTED      ((EFI_STATUS)3)
#define EFI_BUFFER_TOO_SMALL ((EFI_STATUS)(0x8000000000000005ULL))
#define EFI_NOT_FOUND        ((EFI_STATUS)(0x800000000000000eULL))
#define EFI_ERROR(s)         (((INT64)(s)) < 0)
#define EFIERR(x)            ((EFI_STATUS)(0x8000000000000000ULL | (x)))

typedef struct {
	UINT32 Data1;
	UINT16 Data2;
	UINT16 Data3;
	UINT8  Data4[8];
} EFI_GUID;

typedef struct {
	UINT64 Signature;
	UINT32 Revision;
	UINT32 HeaderSize;
	UINT32 CRC32;
	UINT32 Reserved;
} EFI_TABLE_HEADER;

typedef enum {
	AllocateAnyPages,
	AllocateMaxAddress,
	AllocateAddress,
	MaxAllocateType
} EFI_ALLOCATE_TYPE;

typedef enum {
	EfiReservedMemoryType,
	EfiLoaderCode,
	EfiLoaderData,
	EfiBootServicesCode,
	EfiBootServicesData,
	EfiRuntimeServicesCode,
	EfiRuntimeServicesData,
	EfiConventionalMemory,
	EfiUnusableMemory,
	EfiACPIReclaimMemory,
	EfiACPIMemoryNVS,
	EfiMemoryMappedIO,
	EfiMemoryMappedIOPortSpace,
	EfiPalCode,
	EfiPersistentMemory,
	EfiMaxMemoryType
} EFI_MEMORY_TYPE;

typedef struct {
	UINT32 Type;
	UINT32 Pad;
	EFI_PHYSICAL_ADDRESS PhysicalStart;
	EFI_VIRTUAL_ADDRESS  VirtualStart;
	UINT64 NumberOfPages;
	UINT64 Attribute;
} EFI_MEMORY_DESCRIPTOR;

typedef struct {
	EFI_GUID VendorGuid;
	VOID    *VendorTable;
} EFI_CONFIGURATION_TABLE;

typedef struct {
	UINT16 ScanCode;
	CHAR16 UnicodeChar;
} EFI_INPUT_KEY;

typedef struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL;
struct EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL {
	VOID *Reset;
	EFI_STATUS (EFIAPI *OutputString)(EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *, CHAR16 *);
	VOID *TestString;
	VOID *QueryMode;
	VOID *SetMode;
	VOID *SetAttribute;
	VOID *ClearScreen;
	VOID *SetCursorPosition;
	VOID *EnableCursor;
	VOID *Mode;
};

typedef struct EFI_BOOT_SERVICES EFI_BOOT_SERVICES;
struct EFI_BOOT_SERVICES {
	EFI_TABLE_HEADER Hdr;
	/* Task Priority Services */
	VOID *RaiseTPL;
	VOID *RestoreTPL;
	/* Memory Services */
	EFI_STATUS (EFIAPI *AllocatePages)(EFI_ALLOCATE_TYPE, EFI_MEMORY_TYPE, UINTN, EFI_PHYSICAL_ADDRESS *);
	EFI_STATUS (EFIAPI *FreePages)(EFI_PHYSICAL_ADDRESS, UINTN);
	EFI_STATUS (EFIAPI *GetMemoryMap)(UINTN *, EFI_MEMORY_DESCRIPTOR *, UINTN *, UINTN *, UINT32 *);
	EFI_STATUS (EFIAPI *AllocatePool)(EFI_MEMORY_TYPE, UINTN, VOID **);
	EFI_STATUS (EFIAPI *FreePool)(VOID *);
	/* Event & Timer Services */
	VOID *CreateEvent;
	VOID *SetTimer;
	VOID *WaitForEvent;
	VOID *SignalEvent;
	VOID *CloseEvent;
	VOID *CheckEvent;
	/* Protocol Handler Services */
	VOID *InstallProtocolInterface;
	VOID *ReinstallProtocolInterface;
	VOID *UninstallProtocolInterface;
	EFI_STATUS (EFIAPI *HandleProtocol)(EFI_HANDLE, EFI_GUID *, VOID **);
	VOID *Reserved;
	VOID *RegisterProtocolNotify;
	VOID *LocateHandle;
	VOID *LocateDevicePath;
	VOID *InstallConfigurationTable;
	/* Image Services */
	VOID *LoadImage;
	VOID *StartImage;
	VOID *Exit;
	VOID *UnloadImage;
	EFI_STATUS (EFIAPI *ExitBootServices)(EFI_HANDLE, UINTN);
	VOID *GetNextMonotonicCount;
	EFI_STATUS (EFIAPI *Stall)(UINTN);
	VOID *SetWatchdogTimer;
	/* DriverSupport Services */
	VOID *ConnectController;
	VOID *DisconnectController;
	/* Open and Close Protocol Services */
	VOID *OpenProtocol;
	VOID *CloseProtocol;
	VOID *OpenProtocolInformation;
	/* Library Services */
	VOID *ProtocolsPerHandle;
	EFI_STATUS (EFIAPI *LocateHandleBuffer)(UINT32, EFI_GUID *, VOID *, UINTN *, EFI_HANDLE **);
	EFI_STATUS (EFIAPI *LocateProtocol)(EFI_GUID *, VOID *, VOID **);
	VOID *InstallMultipleProtocolInterfaces;
	VOID *UninstallMultipleProtocolInterfaces;
	VOID *CalculateCrc32;
	VOID *CopyMem;
	VOID *SetMem;
	VOID *CreateEventEx;
};

typedef struct EFI_SYSTEM_TABLE EFI_SYSTEM_TABLE;
struct EFI_SYSTEM_TABLE {
	EFI_TABLE_HEADER Hdr;
	CHAR16 *FirmwareVendor;
	UINT32 FirmwareRevision;
	UINT32 _pad;
	EFI_HANDLE ConsoleInHandle;
	VOID *ConIn;
	EFI_HANDLE ConsoleOutHandle;
	EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL *ConOut;
	EFI_HANDLE StandardErrorHandle;
	VOID *StdErr;
	VOID *RuntimeServices;
	EFI_BOOT_SERVICES *BootServices;
	UINTN NumberOfTableEntries;
	EFI_CONFIGURATION_TABLE *ConfigurationTable;
};

/* ---- EFI_FILE_PROTOCOL ---- */
#define EFI_FILE_MODE_READ  0x0000000000000001ULL
#define EFI_FILE_MODE_WRITE 0x0000000000000002ULL
#define EFI_FILE_MODE_CREATE 0x8000000000000000ULL

typedef struct EFI_FILE_PROTOCOL EFI_FILE_PROTOCOL;
typedef EFI_STATUS (EFIAPI *EFI_FILE_OPEN)(EFI_FILE_PROTOCOL *, EFI_FILE_PROTOCOL **, CHAR16 *, UINT64, UINT64);
typedef EFI_STATUS (EFIAPI *EFI_FILE_CLOSE)(EFI_FILE_PROTOCOL *);
typedef EFI_STATUS (EFIAPI *EFI_FILE_READ)(EFI_FILE_PROTOCOL *, UINTN *, VOID *);
typedef EFI_STATUS (EFIAPI *EFI_FILE_GET_INFO)(EFI_FILE_PROTOCOL *, EFI_GUID *, UINTN *, VOID *);
struct EFI_FILE_PROTOCOL {
	UINT64 Revision;
	EFI_FILE_OPEN     Open;
	EFI_FILE_CLOSE    Close;
	VOID             *Delete;
	EFI_FILE_READ     Read;
	VOID             *Write;
	VOID             *GetPosition;
	VOID             *SetPosition;
	EFI_FILE_GET_INFO GetInfo;
	VOID             *SetInfo;
	VOID             *Flush;
};

typedef struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL EFI_SIMPLE_FILE_SYSTEM_PROTOCOL;
struct EFI_SIMPLE_FILE_SYSTEM_PROTOCOL {
	UINT64 Revision;
	EFI_STATUS (EFIAPI *OpenVolume)(EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *, EFI_FILE_PROTOCOL **);
};

typedef struct {
	UINT64   Size;
	UINT64   FileSize;
	UINT64   PhysicalSize;
	UINT8    CreateTime[16];
	UINT8    LastAccessTime[16];
	UINT8    ModificationTime[16];
	UINT64   Attribute;
	CHAR16   FileName[1];
} EFI_FILE_INFO;

#define EFI_GUID_INIT(a,b,c,d0,d1,d2,d3,d4,d5,d6,d7) { a, b, c, { d0,d1,d2,d3,d4,d5,d6,d7 } }
#define EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID \
	EFI_GUID_INIT(0x964e5b22,0x6459,0x11d2,0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b)
#define EFI_FILE_INFO_ID \
	EFI_GUID_INIT(0x09576e92,0x6d3f,0x11d2,0x8e,0x39,0x00,0xa0,0xc9,0x69,0x72,0x3b)
#define EFI_LOADED_IMAGE_PROTOCOL_GUID \
	EFI_GUID_INIT(0x5b1b31a1,0x9562,0x11d2,0x8e,0x3f,0x00,0xa0,0xc9,0x69,0x72,0x3b)
#define EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID \
	EFI_GUID_INIT(0xf4560cf6,0x40ec,0x4b4a,0xa1,0x92,0xbf,0x1d,0x17,0x90,0xb7,0x71)
#define EFI_DXE_SERVICES_TABLE_GUID \
	EFI_GUID_INIT(0x05ad34ba,0x6f02,0x4da2,0x92,0x14,0x00,0x87,0xc1,0x97,0xcf,0x76)

/*
 * PI EFI_DXE_SERVICES.  Only the leading fields are declared, but they are in
 * spec order so SetMemorySpaceAttributes lands on the correct offset.
 */
typedef struct {
	EFI_TABLE_HEADER Hdr;
	VOID *AddMemorySpace;
	VOID *AllocateMemorySpace;
	VOID *FreeMemorySpace;
	VOID *RemoveMemorySpace;
	VOID *GetMemorySpaceDescriptor;
	EFI_STATUS (EFIAPI *SetMemorySpaceAttributes)(EFI_PHYSICAL_ADDRESS, UINT64, UINT64);
	VOID *GetMemorySpaceMap;
	VOID *AddMemorySpaceAttributes;
	VOID *GetMemorySpaceAttributes;
} EFI_DXE_SERVICES;

/* EFI_MEMORY_* attribute bits (UEFI 2.10 table 8) */
#define EFI_MEMORY_UC            0x0000000000000001ULL
#define EFI_MEMORY_WC            0x0000000000000002ULL
#define EFI_MEMORY_WT            0x0000000000000004ULL
#define EFI_MEMORY_WB            0x0000000000000008ULL
#define EFI_MEMORY_XP            0x0000000000004000ULL
#define EFI_MEMORY_RO            0x0000000000020000ULL

typedef struct {
	EFI_STATUS (EFIAPI *GetMemoryAttributes)(VOID *, UINT64, UINT64, UINT64 *);
	EFI_STATUS (EFIAPI *SetMemoryAttributes)(VOID *, UINT64, UINT64, UINT64);
	EFI_STATUS (EFIAPI *ClearMemoryAttributes)(VOID *, UINT64, UINT64, UINT64);
} EFI_MEMORY_ATTRIBUTE_PROTOCOL;

typedef struct {
	UINT32 Revision;
	EFI_HANDLE ParentHandle;
	EFI_SYSTEM_TABLE *SystemTable;
	EFI_HANDLE DeviceHandle;
	VOID *FilePath;
	VOID *Reserved;
	UINT32 LoadOptionsSize;
	VOID *LoadOptions;
	VOID *ImageBase;
	UINT64 ImageSize;
	EFI_MEMORY_TYPE ImageCodeType;
	EFI_MEMORY_TYPE ImageDataType;
	VOID *Unload;
	void *pad_image_handle; /* EFI_HANDLE ImageHandle in newer revs */
} EFI_LOADED_IMAGE;

#endif /* GATEHOUSE_EFI_H */
