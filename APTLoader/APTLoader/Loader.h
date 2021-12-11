#include <iostream>
#include <string>
#include <windows.h>

#define MAX_PAYLOAD_SIZE 64*1024
#define MAX_META_SIZE 256
#define MAX_FILE_NAME 256
typedef int PID;

typedef enum _CODE
{
    CODE_SUCCESS = 1,
    CODE_GET_ALL = 2,
    CODE_GET_ONE = 4,
    CODE_NO_UPDATE = 8,
    CODE_UPDATE = 16,
    CODE_IGNORE_REQUEST = 32,
    CODE_TERMINATE_ONE = 64,
    CODE_TERMINATE_ALL = 128,
    CODE_GET_SESSION_KEY = 256,
    CODE_MY_PUBLIC_KEY = 512,
    CODE_ERROR = -1,
}CTRLCODE;

typedef enum _FTYPE
{
    TEXT = 0,
    BINARY = 1,
    ZIP = 2
}FTYPE;

typedef struct _METADATA
{
    DWORD FileAttributes;
    char Filename[MAX_FILE_NAME];
    size_t Filesize;
    FTYPE FileType;
}METADATA;

typedef struct _Module {
    std::string filename;
    FTYPE ftype;
    HANDLE hProcess;
} Module;

typedef struct _Control {
    CTRLCODE ControlCode;
    CTRLCODE ResponseCode;
    METADATA MetaData;
    BYTE payload[MAX_PAYLOAD_SIZE];
}Control;