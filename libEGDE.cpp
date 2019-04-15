// libEGDE.cpp : 定义控制台应用程序的入口点。
//

#include "stdafx.h"
#include <Windows.h>
#include <strsafe.h>
#include <Sddl.h>
#include <atlstr.h>


#define SECURITY_WIN32
#include <Security.h>
#include <Secext.h>

#pragma comment(lib, "Secur32.lib")


#include "md5.h"

#define _CRT_RAND_S
#include <stdlib.h> 


#define ARRSIZEOF(x) (sizeof(x)/sizeof(x[0]))

BOOL SHGetUserSID(LPTSTR pSid, DWORD cchSize)
{
	if (pSid == NULL || cchSize == 0)
		return FALSE;

	BOOL bRet = FALSE;
	DWORD cbUserSID = 0;
	DWORD cchNameSize = 0;
	DWORD cchDomainSize = 0;
	LPTSTR lpSid = NULL;
	LPVOID lpUserSID = NULL;
	LPWSTR lpDomainName = NULL;
	LPWSTR lpUserName = NULL;
	SID_NAME_USE snu;

	if (GetUserNameEx(NameSamCompatible, lpUserName, &cchNameSize))
		return FALSE;

	lpUserName = (LPWSTR)malloc(cchNameSize * 2);
	if (lpUserName == NULL || !GetUserNameEx(NameSamCompatible, lpUserName, &cchNameSize))
		return FALSE;

	wprintf(L"SHGetUserSID---Current user name: %s\n", lpUserName);

	if (LookupAccountName(NULL, lpUserName, lpUserSID, &cbUserSID, lpDomainName, &cchDomainSize, &snu) ||
		GetLastError() != ERROR_INSUFFICIENT_BUFFER)
	{
		free(lpUserName);
		return FALSE;
	}

	lpUserSID = malloc(cbUserSID);
	if (lpUserSID == NULL)
	{
		free(lpUserName);
		return FALSE;
	}

	lpDomainName = (LPWSTR)malloc(cchDomainSize * 2);
	if (lpDomainName == NULL)
	{
		free(lpUserName);
		free(lpUserSID);
		return FALSE;
	}

	if (LookupAccountName(NULL, lpUserName, lpUserSID, &cbUserSID, lpDomainName, &cchDomainSize, &snu))
	{
		if (ConvertSidToStringSid((PSID)lpUserSID, &lpSid))
		{
			bRet = SUCCEEDED(StringCchCopy(pSid, cchSize, lpSid));

			LocalFree(lpSid);
			lpSid = NULL;
		}
	}

	free(lpUserName);
	free(lpUserSID);
	free(lpDomainName);

	return bRet;
}


BOOL SHGetMachineGuid(LPBYTE lpdata, DWORD dwdatalen)
{
	HKEY hKey;
	
	if (ERROR_SUCCESS != RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Cryptography", 0, 0x20119u, &hKey))
		return FALSE;
    
	if (ERROR_SUCCESS != RegQueryValueExW(hKey, L"MachineGuid", 0, 0, lpdata, &dwdatalen))
	{
		RegCloseKey(hKey);
		return FALSE;
	}
	    
	return TRUE;
}


CONST BYTE PREFIX[]={
	00, 00, 00, 00, 04, 00, 00, 00, 01, 00, 00, 00, 01, 00, 00, 00,
	04, 00, 00, 00, 01, 00, 00, 00, 02, 00, 00, 00
};


// IDA
BOOL CS64_WordSwap(int a1, int a2, DWORD dwSize, DWORD* a4, DWORD* a5)
{
	BOOL bRet = FALSE;
	int v0 = a2;

	if (dwSize < 2 || dwSize & 1)
	{
		bRet = FALSE;
	}
	else
	{
		BOOL b1 = FALSE;
		int v1, v2, v3, v4, v5;

		v1 = *(DWORD *)(a1 + 4) | 1;
		v2 = *(DWORD *)a1 | 1;
		v3 = 0;
		v4 = 0;
		v5 = v2;
		b1 = (dwSize == 1);

		if (dwSize > 1)
		{
			int v6, v7, v8, v9;
			unsigned int v10, v11, v12, v13;

			v8 = v2 + 1778057216;
			v9 = v2 + 1778057216;
			v13 = ((dwSize - 2) >> 1) + 1;

			do
			{
				v10 = (*(DWORD *)v0 + v4) * v8 - 284857861 * ((unsigned int)(*(DWORD *)v0 + v4) >> 16);
				v11 = -359202815 * (2046337941 * v10 + 1755016095 * (v10 >> 16))
					- 1007687017 * ((2046337941 * v10 + 1755016095 * (v10 >> 16)) >> 16);
				v6 = v11 + v3;
				v12 = (*(DWORD *)(v0 + 4) + v11) * (v1 + 333119488) - 1021897765 * ((*(DWORD *)(v0 + 4) + v11) >> 16);
				v8 = v9;
				v4 = 516489217 * (1505996589 * v12 - 573759729 * (v12 >> 16))
					+ 901586633 * ((1505996589 * v12 - 573759729 * (v12 >> 16)) >> 16);
				v7 = dwSize - 2;
				v0 += 8;
				v3 = v4 + v6;
				b1 = (v13-- == 1);
				dwSize -= 2;
			}while (!b1);

			v2 = v5;
			b1 = (v7 == 1);
		}

		if (b1)
		{
			unsigned int v14, v15, v16;

			v14 = (*(DWORD *)v0 + v4) * (v2 + 1778057216) - 284857861 * ((unsigned int)(*(DWORD *)v0 + v4) >> 16);
			v15 = -359202815 * (2046337941 * v14 + 1755016095 * (v14 >> 16))
				- 1007687017 * ((2046337941 * v14 + 1755016095 * (v14 >> 16)) >> 16);
			v16 = 1505996589 * (v15 * (v1 + 333119488) - 1021897765 * (v15 >> 16))
				- 573759729 * ((v15 * (v1 + 333119488) - 1021897765 * (v15 >> 16)) >> 16);
			v4 = 516489217 * v16 + 901586633 * (v16 >> 16);
			v3 += v4 + v15;
		}

		*a4 = v4;
		*a5 = v3;
		bRet = TRUE;
	}

	return bRet;
}


/// IDA
BOOL CS64_Reversible(int a1, int a2, DWORD dwSize, DWORD* a4, DWORD* a5)
{
	int v0;
	unsigned int v1;
	BOOL bRet = FALSE;

	v0 = a2;
	v1 = dwSize;

	if (dwSize < 2 || dwSize & 1)
	{
		bRet = FALSE;
	}
	else
	{
		BOOL b1 = FALSE;
		int v2, v3, v4, v5, v6;

		v2 = *(DWORD *)a1 | 1;
		v5 = *(DWORD *)(a1 + 4) | 1;
		v3 = 0;
		v4 = 0;
		v6 = v2;
		b1 = (dwSize == 1);

		if (dwSize > 1)
		{
			int v7, v8, v9;
			unsigned int v10, v11, v12, v13, v14;

			v14 = ((dwSize - 2) >> 1) + 1;

			do
			{
				v7 = *(DWORD *)v0 + v4;
				v0 += 8;
				v10 = -1324285952 * v2 * v7 - 812076783 * ((unsigned int)(v2 * v7) >> 16);
				v11 = 315537773 * ((1537146880 * v10 - 2029495393 * (v10 >> 16)) >> 16)
					- 1184038912 * (1537146880 * v10 - 2029495393 * (v10 >> 16));
				v8 = 495124480 * v11 + 629022083 * (v11 >> 16);
				v9 = v8 + v3;
				v1 -= 2;
				v12 = 385155072 * v5 * (*(DWORD *)(v0 - 4) + v8)
					- 1569450251 * ((unsigned int)(v5 * (*(DWORD *)(v0 - 4) + v8)) >> 16);
				v13 = 730398720 * (-1761673216 * v12 - 746350849 * (v12 >> 16))
					+ 2090019721 * ((-1761673216 * v12 - 746350849 * (v12 >> 16)) >> 16);
				v2 = v6;
				v4 = -1620508672 * v13 - 1079730327 * (v13 >> 16);
				v3 = v4 + v9;
				--v14;
			}while (v14);

			b1 = (v1 == 1);
		}

		if (b1)
		{
			int v15, v16;
			unsigned int  v17, v18, v19;

			v18 = -1324285952 * v2 * (v4 + *(DWORD *)v0) - 812076783 * ((unsigned int)(v2 * (v4 + *(DWORD *)v0)) >> 16);
			v19 = 315537773 * ((1537146880 * v18 - 2029495393 * (v18 >> 16)) >> 16)
				- 1184038912 * (1537146880 * v18 - 2029495393 * (v18 >> 16));
			v15 = 495124480 * v19 + 629022083 * (v19 >> 16);
			v16 = v15 + v3;
			v17 = 385155072 * v5 * v15 - 1569450251 * ((unsigned int)(v5 * v15) >> 16);
			v4 = -1620508672
				* (730398720 * (-1761673216 * v17 - 746350849 * (v17 >> 16))
				+ 2090019721 * ((-1761673216 * v17 - 746350849 * (v17 >> 16)) >> 16))
				- 1079730327
				* ((730398720 * (-1761673216 * v17 - 746350849 * (v17 >> 16))
				+ 2090019721 * ((-1761673216 * v17 - 746350849 * (v17 >> 16)) >> 16)) >> 16);
			v3 = v4 + v16;
		}

		*(DWORD *)a4 = v4;
		*(DWORD *)a5 = v3;
		bRet = TRUE;
	}

	return bRet;
}


BOOL BuildPatentHash(LPCWSTR str, DWORD cbSize, LPBYTE md5, LPBYTE hash)
{
	if (str == NULL || md5 == NULL || hash == NULL)
		return FALSE;

	DWORD v1, v2, v3, v4, dwSize;

	dwSize = cbSize >> 2;
	if (dwSize & 1)
		--dwSize;

	if ( CS64_WordSwap((int)md5, (int)str, dwSize, &v1, &v2)
		&& CS64_Reversible((int)md5, (int)str, dwSize, &v3, &v4))
	{
		*(DWORD *)hash = v1 ^ v3;
		*(DWORD *)(hash + 4) = v2 ^ v4;

		return TRUE;
	}

	return FALSE;
}


#ifndef b64_malloc
#  define b64_malloc(ptr) malloc(ptr)
#endif
#ifndef b64_realloc
#  define b64_realloc(ptr, size) realloc(ptr, size)
#endif

/**
 * Base64 index table.
 */

static const char b64_table[] = {
  'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
  'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
  'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
  'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
  'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
  'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
  'w', 'x', 'y', 'z', '0', '1', '2', '3',
  '4', '5', '6', '7', '8', '9', '+', '/'
};


char *
b64_encode (const unsigned char *src, size_t len) {
	int i = 0;
	int j = 0;
	char *enc = NULL;
	size_t size = 0;
	unsigned char buf[4];
	unsigned char tmp[3];

	// alloc
	enc = (char *) b64_malloc(1);
	if (NULL == enc) { return NULL; }

	// parse until end of source
	while (len--) {
		// read up to 3 bytes at a time into `tmp'
		tmp[i++] = *(src++);

		// if 3 bytes read then encode into `buf'
		if (3 == i) {
			buf[0] = (tmp[0] & 0xfc) >> 2;
			buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
			buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
			buf[3] = tmp[2] & 0x3f;

			// allocate 4 new byts for `enc` and
			// then translate each encoded buffer
			// part by index from the base 64 index table
			// into `enc' unsigned char array
			enc = (char *) b64_realloc(enc, size + 4);
			for (i = 0; i < 4; ++i) {
				enc[size++] = b64_table[buf[i]];
			}

			// reset index
			i = 0;
		}
	}

	// remainder
	if (i > 0) {
		// fill `tmp' with `\0' at most 3 times
		for (j = i; j < 3; ++j) {
			tmp[j] = '\0';
		}

		// perform same codec as above
		buf[0] = (tmp[0] & 0xfc) >> 2;
		buf[1] = ((tmp[0] & 0x03) << 4) + ((tmp[1] & 0xf0) >> 4);
		buf[2] = ((tmp[1] & 0x0f) << 2) + ((tmp[2] & 0xc0) >> 6);
		buf[3] = tmp[2] & 0x3f;

		// perform same write to `enc` with new allocation
		for (j = 0; (j < i + 1); ++j) {
			enc = (char *) b64_realloc(enc, size + 1);
			enc[size++] = b64_table[buf[j]];
		}

		// while there is still a remainder
		// append `=' to `enc'
		while ((i++ < 3)) {
			enc = (char *) b64_realloc(enc, size + 1);
			enc[size++] = '=';
		}
	}

	// Make sure we have enough space to add '\0' character at end.
	enc = (char *) b64_realloc(enc, size + 1);
	enc[size] = '\0';

	return enc;
}


char __stdcall EscapeString(char **pszEscaped, const char *szBuffer)
{
	const char *v2; // ebp@1
	char v3; // al@1
	int v4; // edx@1
	const char *v5; // esi@2
	signed int v6; // ecx@11
	int v7; // edi@14
	HANDLE v8; // eax@14
	char *v9; // esi@14
	char v10; // cl@17
	signed int v11; // eax@17
	int v12; // eax@27
	char result; // al@32

	v2 = szBuffer;
	v3 = *szBuffer;
	v4 = 0;
	if ( *szBuffer )
	{
		v5 = szBuffer + 1;
		do
		{
			if ( (unsigned __int8)v3 < 0x5Bu && (unsigned __int8)v3 >= 0x41u
				|| (unsigned __int8)v3 >= 0x61u && (unsigned __int8)v3 < 0x7Bu
				|| (unsigned __int8)v3 < 0x3Bu && (unsigned __int8)v3 >= 0x2Du )
			{
LABEL_4:
				if ( (unsigned __int8)(v3 - 32) <= 0x5Eu )
					goto __LABEL_5;
			}
			else
			{
				switch ( v3 )
				{
				default:
					goto LABEL_4;
				case 32:
				case 34:
				case 35:
				case 36:
				case 37:
				case 38:
				case 43:
				case 44:
				case 59:
				case 60:
				case 61:
				case 62:
				case 63:
				case 64:
				case 91:
				case 92:
				case 93:
				case 94:
				case 96:
				case 123:
				case 124:
				case 125:
					break;
				}
			}
			v6 = 3;
			if ( v3 == 32 )
__LABEL_5:
			v6 = 1;
			v3 = *v5++;
			v4 += v6;
		}
		while ( v3 );
	}
	v7 = v4 + 1;
	v8 = GetProcessHeap();
	v9 = (char *)HeapAlloc(v8, 8u, v7);
	*pszEscaped = v9;
	if ( !v9 )
		goto LABEL_33;
	if ( *szBuffer )
	{
		do
		{
			if ( !v7 )
				goto LABEL_33;
			v10 = *v2;
			v11 = *v2;
			if ( v11 < 91 && v11 >= 65 || v11 >= 97 && v11 < 123 || v11 < 59 && v11 >= 45 )
			{
LABEL_12:
				if ( (unsigned __int8)(v10 - 32) <= 0x5Eu )
				{
					*v9 = v10;
LABEL_14:
					++v9;
					--v7;
					goto LABEL_15;
				}
			}
			else
			{
				switch ( v11 )
				{
				default:
					goto LABEL_12;
				case 32:
				case 34:
				case 35:
				case 36:
				case 37:
				case 38:
				case 43:
				case 44:
				case 59:
				case 60:
				case 61:
				case 62:
				case 63:
				case 64:
				case 91:
				case 92:
				case 93:
				case 94:
				case 96:
				case 123:
				case 124:
				case 125:
					break;
				}
			}
			if ( v10 == 32 )
			{
				*v9 = 43;
				goto LABEL_14;
			}
			v12 = sprintf_s(v9, v7, "%%%02x", v10);
			v9 += v12;
			v7 -= v12;
LABEL_15:
			++v2;
		}
		while ( *v2 );
	}
	if ( v7 )
	{
		*v9 = 0;
		result = 1;
	}
	else
	{
LABEL_33:
		result = 0;
	}
	return result;
}


// 
unsigned int ObfuscateData(BYTE *data, unsigned int dataSize, BYTE **obfuscatedData, unsigned int *obfuscatedDataSize)
{
	unsigned int v5; // ebp@1
	SIZE_T v6; // ebx@1
	unsigned int v7; // edi@1
	BYTE *v8; // esi@1
	HANDLE v9; // eax@1
	BYTE *v10; // eax@1
	unsigned int v11; // ebx@2
	unsigned int v12; // edx@2
	BYTE *i; // ecx@2
	char v14; // al@4
	unsigned int v15; // edx@6
	int v16; // ecx@7
	char v17; // al@8
	unsigned int result; // eax@9

	v5 = dataSize;
	v6 = dataSize + 4;
	v7 = 0;
	v8 = data;
	*obfuscatedDataSize = dataSize + 4;
	v9 = GetProcessHeap();
	v10 = (BYTE *)HeapAlloc(v9, 8u, v6);
	*obfuscatedData = v10;
	if ( v10 )
	{
		
		rand_s(&v11);
		v12 = v5 >> 2;
		*(DWORD *)v10 = v11;
		for ( i = v10 + 4; v12; --v12 )
		{
			v11 = 214013 * v11 + 2531011;
			dataSize = v11;
			do
			{
				v14 = *v8 ^ *((BYTE *)&dataSize + v7++);
				*i = v14;
				++v8;
				++i;
			}
			while ( v7 < 4 );
			v7 = 0;
		}
		dataSize = 214013 * v11 + 2531011;
		v15 = 0;
		if ( v5 & 3 )
		{
			v16 = i - v8;
			do
			{
				v17 = *v8 ^ *((BYTE *)&dataSize + v15++);
				(v8++)[v16] = v17;
			}
			while ( v15 < (v5 & 3) );
		}
		result = 0;
	}
	else
	{
		result = 0x8007000E;
	}
	return result;
}


#define edge_1 L"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\CurrentVersion\\AppContainer\\Storage\\microsoft.microsoftedge_8wekyb3d8bbwe\\MicrosoftEdge\\Protected - It is a violation of Windows Policy to modify. See aka.ms/browserpolicy"

int _tmain(int argc, _TCHAR* argv[])
{
    CString strSid;
	CString strMachineGuid;
	CString strUrl = L"https://github.com/binbibi/libedge";
    CString strBlob;
	LPBYTE lpBLOB = NULL;


	WCHAR szSid[100] = {0};
	WCHAR szMachineGuid[100] = {0};

	if (!SHGetUserSID(szSid, ARRSIZEOF(szSid)))
	{
		return FALSE;
	}

	if (!SHGetMachineGuid(LPBYTE(szMachineGuid), sizeof(szMachineGuid)))
	{
		return FALSE;
	}
	
	strSid= szSid;
	strMachineGuid = szMachineGuid;
	strBlob = strSid + L"-" + strMachineGuid;

    DWORD dwBlob = 28 + 4 + (strUrl.GetLength()+1)*2 + strBlob.GetLength()*2;
    lpBLOB = (LPBYTE)malloc(dwBlob);
	memset(lpBLOB, 0, dwBlob);
	DWORD dwstrlen = (strUrl.GetLength()+1)*2;// 需要把0算进去
	
    memcpy(lpBLOB, PREFIX, 28);
	memcpy(lpBLOB+ 28, &dwstrlen, 4);
	memcpy(lpBLOB+ 32, (LPBYTE)strUrl.GetString(), dwstrlen);
	memcpy(lpBLOB+ 32 + (strUrl.GetLength()+1)*2, (LPBYTE)strBlob.GetString(), strBlob.GetLength()*2);

	unsigned char decrypt[16];
	BYTE patentHash[8] = {0};

	MD5_CTX md5;  
	MD5Init(&md5);
	MD5Update(&md5, (unsigned char *)lpBLOB, dwBlob);  
	MD5Final(decrypt, &md5);   
    
	
	BuildPatentHash((LPCWSTR)lpBLOB, dwBlob, (LPBYTE)decrypt, (LPBYTE)&patentHash);

	//DWORD dwbase641 = 0;
	//unsigned char* base641 =  base64_encode(patentHash, 8, (size_t*) &dwbase641);
	
	// EDGE里面也计算了这个;但是没有使用basedecryptEscape参与下面的进一步计算
	char* basedecrypt = b64_encode(decrypt, 0x10);
    char* basedecryptEscape = NULL;
	EscapeString(&basedecryptEscape, (const char *)basedecrypt);
    
	char* basehash = b64_encode(patentHash, 0x8);
	char* basehashEscape = NULL;
	EscapeString(&basehashEscape, (const char *)basehash);
	DWORD dwbasehashEscape = strlen(basehashEscape);
    
	DWORD dwbuffertlv = 4 + 4 + 32 + dwstrlen + 4 + 4 + dwbasehashEscape;
	LPBYTE  lpbuffertlv = (LPBYTE)malloc(dwbuffertlv);
	memset(lpbuffertlv, 0, dwbuffertlv);
	
	DWORD dwg1 =1; 
	DWORD dwg1len = 32 + dwstrlen;
	DWORD dwg2 = 2;
	DWORD dwg2len = dwbasehashEscape;  
	memcpy(lpbuffertlv, &dwg1, 4);
	memcpy(lpbuffertlv+4, &dwg1len, 4);
	memcpy(lpbuffertlv+4+4, lpBLOB, 32 + dwstrlen);
	memcpy(lpbuffertlv+4+4+32 + dwstrlen, &dwg2, 4);
	memcpy(lpbuffertlv+4+4+32 + dwstrlen +4, &dwg2len, 4);
	memcpy(lpbuffertlv+4+4+32 + dwstrlen +4+4, basehashEscape, dwbasehashEscape);


	// 计算这个
    LPBYTE assasa = NULL;
	DWORD dsasd = 0;
	ObfuscateData(lpbuffertlv, dwbuffertlv, &assasa, (unsigned int*)&dsasd);

    // 
	LPBYTE  lpProtectedHomepages = (LPBYTE)malloc(dsasd+4);
	memcpy(lpProtectedHomepages, &dwg1, 4);
	memcpy(lpProtectedHomepages+4, assasa, dsasd);

	HKEY hOpenedKey = NULL;
	LONG nResult = RegOpenKeyEx(HKEY_CURRENT_USER, edge_1, 0, KEY_READ|KEY_WRITE, &hOpenedKey);
	RegSetValueEx(hOpenedKey, L"ProtectedHomepages", NULL, REG_BINARY, lpProtectedHomepages, dsasd+4);

	free(lpBLOB);
	lpBLOB = NULL;

	return 0;
}

