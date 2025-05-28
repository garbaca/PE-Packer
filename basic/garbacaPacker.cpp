#include<Windows.h>
#include<winnt.h>
#include<iostream>
#include<random>
#include<time.h>
#include<vector>
using namespace std;
#define loop(a,b,c,d) for (int a=b;a<c;a+=d)
#define pub push_back
using QWORD=u_int64;
using ull=unsigned long long;
using QWORD_PTR=ull;

//Global variable
LPVOID fileMapView=nullptr;
PIMAGE_DOS_HEADER dos_h=nullptr;
PIMAGE_NT_HEADERS nt_h=nullptr;
PIMAGE_SECTION_HEADER txtSec_h=nullptr;
vector<PIMAGE_SECTION_HEADER> secHdr;
QWORD key=0;
const char shellCode[]={(char)0x48, (char)0xB8, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0x48, (char)0x89, (char)0xC1, (char)0x48, (char)0xBB, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0x48, (char)0x01, (char)0xD9, (char)0x48, (char)0xBA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0x48, (char)0x31, (char)0x50, (char)0x01, (char)0x48, (char)0xFF, (char)0xC0, (char)0x48, (char)0x39, (char)0xC8, (char)0x75, (char)0xF4, (char)0x48, (char)0xB8, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0xAA, (char)0x50, (char)0xC3};
QWORD shellSize=sizeof(shellCode);

bool generateFileMapping(const char* fileName, QWORD extraSize)
{
	printf("Mapping PE file ...\n");
	HANDLE fileHandle = INVALID_HANDLE_VALUE;
	loop(i,0,10,1)
	{
		fileHandle=CreateFile(fileName,GENERIC_READ | GENERIC_WRITE,0,0,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,0);
		if (fileHandle==INVALID_HANDLE_VALUE)
		{
			if (GetLastError()==ERROR_SHARING_VIOLATION)
			{
				Sleep(1000);
			}
			else
			{
				break;
			}
		}
		else
		{
			break;
		}
	}
	if (fileHandle==INVALID_HANDLE_VALUE)
	{
		printf("Can't read file. Error code: 0x%X\n",GetLastError());
		return 0;
	}
	int fileSize=GetFileSize(fileHandle,NULL)+extraSize;
	HANDLE fileMapping=CreateFileMapping(fileHandle,NULL,PAGE_READWRITE,0,fileSize,NULL);
	if (fileMapping==INVALID_HANDLE_VALUE)
	{
		printf("Can't create file mapping object. Error code: 0x%X\n",GetLastError());
		return 0;
	}
	fileMapView=MapViewOfFile(fileMapping,FILE_MAP_ALL_ACCESS,0,0,fileSize);
	if (fileMapView==nullptr)
	{
		printf("Can't create map view of file. Error code: 0x%X\n",GetLastError());
		return 0;
	}
	return 1;
}

PIMAGE_SECTION_HEADER getSectionByCharacteristic(QWORD characteristic)
{
	for (auto i:secHdr)
	{
		if ((i->Characteristics&characteristic))	
		{
			return i;
		}	
	}	
	return nullptr;
}
PIMAGE_SECTION_HEADER getSectionByName(const char* name)
{
	for (auto i:secHdr)
	{
		if (!strcmp((const char*)i->Name,name))
		{
			return i;
		}
	}
	return nullptr;
}
bool validate(LPVOID fileMapView)
{
	printf("Reading PE file ...\n");
	dos_h=(PIMAGE_DOS_HEADER)(fileMapView);
	if (dos_h->e_magic!=(WORD)'ZM')
	{
		printf("This isn't a PE file!\n");
		return 0;
	}
	nt_h=(PIMAGE_NT_HEADERS)((QWORD_PTR)dos_h+dos_h->e_lfanew);
	if (nt_h->Signature!=(WORD)'EP')
	{
		printf("This isn't a PE file!\n");
		return 0;
	}
	return 1;
}
void setSectionHeaderList()
{
	PIMAGE_SECTION_HEADER firstSection=(PIMAGE_SECTION_HEADER)((QWORD_PTR)(nt_h)+sizeof(IMAGE_NT_HEADERS));
	loop(i,0,nt_h->FileHeader.NumberOfSections,1)
	{
		secHdr.pub(firstSection+i);
		//printf("RVA: 0x%X, name: %s\n",secHdr.back()->VirtualAddress,secHdr.back()->Name);
	}	
}
bool patchBytesByVal(QWORD &stubBase, QWORD shellSize, LPVOID newValPtr, QWORD valLookFor)
{
	loop(i,0,shellSize,1)
	{
		if (*(QWORD*)(stubBase+i)==valLookFor)
		{
			memcpy((LPVOID)(stubBase+i),newValPtr,sizeof(QWORD));
			return 1;
		}
	}
	return 0;
}
void disableSection(const char* name)
{
	PIMAGE_SECTION_HEADER relocSecHdr=getSectionByName(name);
	if (relocSecHdr!=nullptr)
	{
		relocSecHdr->Characteristics^=IMAGE_SCN_MEM_READ;
	}
}
void pack()
{
	srand(time(NULL));
	key=rand()%256;
	QWORD base=(QWORD_PTR)fileMapView+(QWORD)txtSec_h->PointerToRawData;
	loop(i,1,(QWORD)txtSec_h->Misc.VirtualSize,1)
	{
		*(BYTE*)(base+i)^=key;
	}
	txtSec_h->Characteristics = IMAGE_SCN_CNT_CODE|IMAGE_SCN_CNT_INITIALIZED_DATA|IMAGE_SCN_MEM_EXECUTE|IMAGE_SCN_MEM_READ|IMAGE_SCN_MEM_WRITE;	
	QWORD oldEIP=nt_h->OptionalHeader.ImageBase+nt_h->OptionalHeader.AddressOfEntryPoint, newEIP=txtSec_h->VirtualAddress+txtSec_h->Misc.VirtualSize;
	nt_h->OptionalHeader.AddressOfEntryPoint=newEIP;
	txtSec_h->Misc.VirtualSize+=shellSize;
	QWORD stubBase=(QWORD_PTR)fileMapView+txtSec_h->PointerToRawData+txtSec_h->Misc.VirtualSize-shellSize;
	QWORD start=nt_h->OptionalHeader.ImageBase+txtSec_h->VirtualAddress,size=txtSec_h->Misc.VirtualSize-shellSize;
	memcpy((LPVOID)stubBase,shellCode,shellSize);
	if (!patchBytesByVal(stubBase,shellSize,&start,0xAAAAAAAAAAAAAAAA))
	{
		printf("Can't add the starting address of shellcode!\n");
		return ;
	}
	if (!patchBytesByVal(stubBase,shellSize,&size,0xAAAAAAAAAAAAAAAA))
	{
		printf("Can't add the size of shellcode!\n");
		return ;
	}
	if (!patchBytesByVal(stubBase,shellSize,&key,0xAAAAAAAAAAAAAAAA))
	{
		printf("Can't add the encryption key!\n");
		return ;
	}
	if (!patchBytesByVal(stubBase,shellSize,&oldEIP,0xAAAAAAAAAAAAAAAA))
	{
		printf("Can't add the old EIP!\n");
		return ;
	}
}
int main(int argc, char* argv[])
{
	if (argc!=2)
	{
		printf("[+] Usage: ./garbacaPacker <path_to_file_name>\n");
		return 1;
	}
	if (generateFileMapping(argv[1],shellSize))
	{
		if (validate(fileMapView))
		{
			setSectionHeaderList(); nt_h->OptionalHeader.DllCharacteristics^=0x40;
            for (auto i:secHdr)
            {
                if (i->Characteristics==0x40000040)	
                {
            		printf("Char: 0x%X, RVA: 0x%X, name: %s @@\n",i->Characteristics,i->VirtualAddress,i->Name);
                }	
            }
			txtSec_h=getSectionByCharacteristic(IMAGE_SCN_CNT_CODE);
			if (txtSec_h==nullptr)
			{
				printf("Can't find text section!\n");
				return 1;
			}
			printf("Ready to pack...\n");
			pack();
		}
		else
		{
			printf("Input file isn't a PE file!\n");
			return 1;
		}
	}	
	else
	{
		printf("Can't create file mapping object. Exiting ...\n");
		return 1;
	}
}
