/**
 * Author : Yekuuun
 * Github : https://github.com/Yekuuun
 * Subject : playing with PE file on a windows x64 env discovering how to manipulate this lind of files.
*/

#include "utils.h"
#include "mapper.h"

//function declaration.
BYTE* ManualRead(IN const LPSTR filePath, OUT DWORD &loadedSize);
VOID showBanner();

//program entry point.
int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        std::cout << "[-] Must pass one argument : ./run-pe <filename>" << std::endl;
        return EXIT_FAILURE;
    }

#ifdef _WIN64
    std::cout << "[*] 64-bit version ok" << "\n";
#else
    return EXIT_FAILURE;
#endif

    //program beginning.
    const LPSTR filePath = argv[1];

    DWORD loadedSize = 0;
    BYTE* rawPE = ManualRead(filePath, loadedSize);
    if(rawPE == nullptr)
    {
        return EXIT_FAILURE;
    }

    showBanner();
    std::cout << "[*] Path to file : " << filePath << std::endl;
    std::cout << "[*] Sizeof loaded file :" << loadedSize << " bytes" << std::endl;

    if(!GetPEInformations(rawPE, loadedSize))
    {
        std::cout << "[-] ERROR loading file." << std::endl;
        return EXIT_FAILURE;
    }

    std::cout << "[*] Operation successfully made. \n\n[:)] Ciao." << std::endl;
    free(rawPE);
    return EXIT_SUCCESS;
}

/**
 * Readfile base on a filepath passed
 * @param filePath : path to a PE file.
 * @param fileSize : ptr to size of file.
 */
BYTE* ManualRead(IN const LPSTR filePath, OUT DWORD &loadedSize)
{
    HANDLE hFile      = NULL;
    LPCSTR pathToFile = filePath;
    
    //creating file.
    hFile = CreateFileA(pathToFile, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if(hFile == NULL || hFile == INVALID_HANDLE_VALUE)
    {
        std::cout << "[-] Opening the file :" << pathToFile << " has failed." << std::endl;
        return nullptr;
    }

    //get size of file
    DWORD sizeOfFile = GetFileSize(hFile, NULL);
    if(sizeOfFile == INVALID_FILE_SIZE)
    {
        std::cout << "[-] Error getting size of file." << std::endl;
        if(hFile)
        {
            CloseHandle(hFile);
        }
        return nullptr;
    }

    BYTE* rawPE = new BYTE[sizeOfFile]; //creating a BYTE[] based on size of file returned.

    //read file
    if(!ReadFile(hFile, rawPE, sizeOfFile, NULL, NULL))
    {
        std::cout << "[-] Error reading the file." << std::endl;
        if(hFile)
        {
            CloseHandle(hFile);
        }

        free(rawPE);
        return nullptr;
    }

    loadedSize = sizeOfFile;
    CloseHandle(hFile);
    return rawPE;
}

/**
 * Showbanner function to display project banner.
 */
VOID showBanner() {
    std::cout << "--------------------------------------------------------" << std::endl;
    const std::string pink = "\033[38;5;205m";
    const std::string reset = "\033[0m";

    std::cout << pink << R"(
    ____  ______     __  ___                           
   / __ \/ ____/    /  |/  /___ _____  ____  ___  _____
  / /_/ / __/______/ /|_/ / __ `/ __ \/ __ \/ _ \/ ___/
 / ____/ /__/_____/ /  / / /_/ / /_/ / /_/ /  __/ /    
/_/   /_____/    /_/  /_/\__,_/ .___/ .___/\___/_/     
                             /_/   /_/                 
    )" << reset << std::endl;

    std::cout << "-----------------A base x64 PE file mapper---------------\n" << std::endl;
}