// $OsBootCompiler.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <iostream>
#include <Windows\Executable\WinPe2.h>
#include <Windows\Executable\WinPeMod2.h>
#include <Core\FileStream.h>
#include <Core\Cybernated API.h>
using namespace Cybernated::Windows::Executable;
using namespace Cybernated::Core::IO;
using namespace Cybernated::Core;
using namespace Cybernated::API;
using namespace Cybernated::Core::Executable;
using namespace Cybernated::Standard;
int main(int argc, char * argv[])
{
	if (argc < 3)
	{
		std::cout << "Too few arguments. Type /? or /h to display command help\n";
		return -1;
	}

	
	AsciiString bootFileName = AsciiString(argv[1]);
	AsciiString kernelFileName = AsciiString(argv[2]);
	bootFileName.copyFrom(".asm", bootFileName.length());
	AsciiString kernelBinFileName = AsciiString(argv[1]);
	kernelBinFileName.copyFrom(".bin", kernelBinFileName.length());										//Create the bin filename the kernel will be compiled to
	FileStream * kernelFile = nullptr;
	FileStream * bootFile = nullptr;
	FileStream * kernelBinFile = nullptr;
	WinPe2 * peFile = nullptr;
	ArrayStd<MemoryLocation *> * sections = nullptr;
	//Initialize the NASM command line 

#ifdef _DEBUG
	AsciiString nasmFileCommandLine = AsciiString("..\\NASM\\nasm.exe  -f bin "); //-i BUILD
#else
	AsciiString nasmFileCommandLine = AsciiString("NASM\\nasm.exe -i BUILD\\ -f bin ");
#endif
	
	nasmFileCommandLine.copyFrom(argv[1], nasmFileCommandLine.length());
	nasmFileCommandLine.copyFrom(".asm -o ", nasmFileCommandLine.length());
	nasmFileCommandLine.copyFrom(argv[1], nasmFileCommandLine.length());
	nasmFileCommandLine.copyFrom(".bin", nasmFileCommandLine.length());
	//Execute the nasm command to compile 
	if (system(nasmFileCommandLine.getData()))
	{
		std::cout << "The NASM command failed\n";
		return -1;
	}
	
	try
	{
		//Open the binary file
		kernelBinFile = createFileStream(&kernelBinFileName, (unsigned long long)ShareMode::Write, (unsigned long long)CreationDisposition::OpenExisting, 
			(unsigned long long)StreamMode::WRITE_ACCESS, (unsigned long long)FileAttributes::None, (unsigned long long)FileFlags::None, (unsigned long long)FileSQOS::None);

		//Open the kernel file as a portable executable
		kernelFile = createFileStream(&kernelFileName, (unsigned long long)ShareMode::Read | (unsigned long long)ShareMode::Write, (unsigned long long)CreationDisposition::OpenExisting, 
			(unsigned long long)StreamMode::READ_ACCESS | (unsigned long long)StreamMode::WRITE_ACCESS, 
			(unsigned long long)FileAttributes::None, (unsigned long long)FileFlags::None, (unsigned long long)FileSQOS::None);
		peFile = new WinPe2(kernelFile, true, true);
		
		//Make sure the PE file is valid for a kernel
		if (peFile->getImportLibrary())		throw CORE_ERROR(CoreErrorCode::BAD_ARGUMENT, L"The specified kernel file contains imports");
		
		//Calculate the physical address to where the image will be loaded (make sure it is aligned properly)
		unsigned long long base = 0x0F000;
		base += kernelBinFile->length();
		size_t sectionAlignment = peFile->getSectionMemoryAlignment();
		if (base % peFile->getSectionMemoryAlignment())
			base += peFile->getSectionMemoryAlignment() - base % peFile->getSectionMemoryAlignment();
		size_t oldKernelBaseSize = base - 0x0F000;
		//Apply base relocations to the kernel
		WinPeMod2 modifier = WinPeMod2(peFile);
		modifier.applyRelocationsForAddress(base);

		//Extract the initialized data and code segments
		sections = peFile->getSectionsDataMarkedAs((unsigned long long)SectionCriteria::EXECUTABLE | (unsigned long long)SectionCriteria::INITIALIZED_DATA | (unsigned long long)SectionCriteria::UNITIALIZED_DATA);
		unsigned int entry = peFile->getEntryPointRVA();
		entry += (unsigned int)base;
		
		size_t size = 0;
		size_t maxIndex = 0;
		unsigned long long maxAddress = 0;
		//Calculate the max memory needed (including uninitialized data segments). Make sure the whole file is less than 64k
		for (size_t i = 0; i < sections->length(); i++)
		{
			if (sections->operator[](i)->getRVA() > maxAddress)
			{
				maxAddress = sections->operator[](i)->getRVA();
				maxIndex = i;
			}
		}
		size = sections->operator[](maxIndex)->getRVA() + sections->operator[](maxIndex)->getLength();
		bootFile = createFileStream(&bootFileName, (unsigned long long)ShareMode::Read, (unsigned long long)CreationDisposition::OpenExisting, 
			(unsigned long long)StreamMode::READ_ACCESS | (unsigned long long)StreamMode::WRITE_ACCESS, (unsigned long long)FileAttributes::None, (unsigned long long)FileFlags::None, (unsigned long long)FileSQOS::None);
		char * buffer = (char*)malloc(bootFile->length());
		if (!buffer)	throw CORE_ERROR(CoreErrorCode::OUT_OF_MEMORY, nullptr);
		//Modify the boot asm file to contain the kernel entry point
		if (bootFile->read((void*)buffer, 0, bootFile->length()) != bootFile->length())
			throw CORE_ERROR(CoreErrorCode::EOF_REACHED, nullptr);
		//Search the buffer for the string
		for (int i = 0; i < bootFile->length() - 30; i++)
		{
			if (memcmp((void const *)((uintptr_t)buffer + i), (void const *)"CPP_ENTRY_POINT EQU ",20) != 0)
				continue;
			for (int j = 9; j >= 0; j--)
			{
				buffer[i + 20 + j] = entry % 10 + 0x30;
				entry /= 10;
			}
		}
		bootFile->seek(0, Cybernated::Core::IO::SeekPosition::START);
		bootFile->write((void const *)buffer, 0, bootFile->length());
		bootFile->flush();
		
		char const * data = nasmFileCommandLine.getData();
		//Recompile the boot file
		if (system(nasmFileCommandLine.getData()))
			throw CORE_ERROR(CoreErrorCode::UNIDENTIFIED_ERROR, L"The NASM Command Failed");

		//Make sure the binary file did not change dramatically to fail compiling
		if (kernelBinFile->length() > oldKernelBaseSize)
			throw CORE_ERROR(CoreErrorCode::CONVERSION_NOT_POSSIBLE, L"The kernel binary size changed");
		//Add the code and initialized data segments to the binary compiled boot file. Make sure sections are aligned properly
		unsigned long long maxSize = 0;
		for (size_t i = 0; i < sections->length(); i++)
		{
			MemoryLocation * ptr = sections->operator[](i);
			kernelBinFile->seek(oldKernelBaseSize + ptr->getRVA(), IO::SeekPosition::START);
			if (ptr->getLocation())
			{
				kernelBinFile->write(ptr->getLocation(), 0, ptr->getLength());
				if (kernelBinFile->currentPosition() > maxSize)
					maxSize = kernelBinFile->currentPosition();
			}
				
			
		}
		if (kernelBinFile->currentPosition() % 512)
			kernelBinFile->seek(512 - kernelBinFile->currentPosition() % 512, SeekPosition::CURRENT);
		//Save and close all files
		kernelBinFile->flush();
	}
	catch (CsError const & e)
	{
		std::cout << "An error occurred in " << e.getFileName() << "\nAt line number: " << e.getLineNumber() << "\n";
	}
	catch (...)
	{
		std::cout << "An unknown error occurred\n";
	}
	delete kernelFile;
	delete kernelBinFile;
	delete bootFile;
	delete peFile;
	if (sections)
		for (size_t i = 0; i < sections->length(); i++)
			delete sections->operator[](i);
	delete sections;
    return 0;
}

