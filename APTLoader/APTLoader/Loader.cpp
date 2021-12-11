#include <iostream>
#include <fstream>
#include <vector>
#include <windows.h>
#include <string>
#include "sodium.h"
#include "Utils.h"
#include "Loader.h"

std::string root = Utils::StdGetEnv("HOMEDRIVE");
std::string homedir = Utils::StdGetEnv("HOME");
std::string homepath = root.append(homedir);
std::string configFile = root.append("config.cfg"); 
std::vector<Module*> modules;


int main()
{
	int ret = sodium_init();
	if (ret < 0)
	{
		MessageBeep(MB_ICONERROR);
		MessageBoxA(GetDesktopWindow(), "Could not initilize libsodium", "Error", MB_ICONERROR || MB_OK);
		return ret;
	}
	BOOL bStatus = FALSE;
	Control ctrl;

	//If not running in elevated mode terminate
	if (!Utils::IsProcessElevated())
	{
		MessageBeep(MB_ICONERROR);
		MessageBoxA(GetDesktopWindow(), "Run as Administrator", "Error", MB_ICONERROR||MB_OK);
		ExitProcess(-1);
	}

	//If config File does not exist create it
	// If it exist load it.
	if (!Utils::FileExists(configFile))
	{
		bStatus = Utils::createFile(configFile, "w");
		if (bStatus)
			_asm{nop};
	}
	else
	{
		Utils::LoadConfig cfg{ configFile };
		cfg.load();
		modules = cfg.modules;
	}

	bStatus = Utils::FileExists(configFile);
	if (bStatus)
	{
		for (size_t i = 0; i < modules.size(); i++)
		{
			Module* m = modules[i];
			FTYPE ftype = m->ftype;
			if (ftype == TEXT)
				m->hProcess = Utils::StdCreateProcess("pyw.exe", m->filename);
			else
				m->hProcess = Utils::StdCreateProcess(m->filename);
		}
	}
	return 0;
}



