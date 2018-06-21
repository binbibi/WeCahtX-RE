#include "stdafx.h"
#include "tucktxs.h"
#include "mhook-lib/mhook.h"
#include "FSearch.h"
#include "OutPutDebug.h"
#include "md5.h"
#include "cJSON.h"
#include "DecryptDB.h"

#include <strsafe.h>

HANDLE g_DbSleepEvent = NULL;

// Hook������ԭ��
typedef VOID(_stdcall* TxParseMsg)();

typedef VOID(_stdcall* TxParseMsgX)();

typedef VOID(_stdcall* TxParseMsgX2)();

typedef int (*Wechatsqlite3Step)(PVOID p);



// Hook�����ĵ�ַ
TxParseMsg    RelTxParseMsg = NULL;
TxParseMsgX   RelTxParseMsgX = NULL;
TxParseMsgX2  RelTxParseMsgX2 = NULL;
Wechatsqlite3Step RelWechatsqlite3Step = NULL;

BOOL GetPEVersion(LPCWSTR path, DWORD *msver, DWORD *lsver)
{
	BOOL status = FALSE;
	PVOID info = NULL;
	DWORD handle = 0;
	VS_FIXEDFILEINFO* vsinfo = NULL;
	UINT vsinfolen = 0;
	DWORD infolen = GetFileVersionInfoSizeW(path, &handle);

	if (infolen)
	{
		info = malloc(infolen);
		if (info)
		{
			if (GetFileVersionInfoW(path, handle, infolen, info))
			{
				if (VerQueryValue(info, _T("\\"), (void**)&vsinfo, &vsinfolen))
				{
					if (msver)
					{
						*msver = vsinfo->dwFileVersionMS;
					}

					if (lsver)
					{
						*lsver = vsinfo->dwFileVersionLS;
					}

					status = TRUE;
				}
			}

			free(info);
		}
	}

	return status;
}


VOID SimpleHexPrint(BYTE* szKey, DWORD dwKeySize)
{
	CString csKey;
	CString cstmp;

	for (int i = 0; i<dwKeySize; i++)
	{
		cstmp.Format(L"%02X", szKey[i]);
		csKey += cstmp;
		cstmp.Empty();
	}

	MyAtlTraceW(L"[%s] ��Կ��%s \n", __FUNCTIONW__,csKey.GetString());
}


VOID __stdcall DUMPSqliteKey(BYTE* szKey, DWORD dwKeySize)
{
	static BOOL bEnter = FALSE;

	if (!bEnter)
	{
		BYTE* szMyKey = (BYTE*)malloc(dwKeySize);
		memcpy(szMyKey, szKey, dwKeySize);
		SimpleHexPrint(szMyKey, dwKeySize);
		bEnter = TRUE;
	}
	
	return;
}


VOID __stdcall DUMPDataBase(LPSTR* lpPath)
{
	MyAtlTraceA("[%s] ����·�� %s \n", __FUNCTION__, lpPath);
	return;
}


VOID __stdcall ParseMMmsg(LPVOID lpinfo)
{
	LPSTR lpFromsztalker; //lpTosztalker;
	DWORD dwMsgType = 0, dwtime, dwseq;
	LPSTR lpMsg;
	PLARGE_INTEGER psrvid = NULL;
    
	__asm
	{
		//int 3;
	}
	
	// String �ṹ
	if (*(PDWORD(lpinfo) + 5) >= 0x10)
	{
		lpFromsztalker = *((LPSTR*)(lpinfo));
	}
	else
	{
		lpFromsztalker = (LPSTR)lpinfo;
	}

	CString strFromsztalker = CA2W(lpFromsztalker, CP_UTF8);

	// type
	dwMsgType = *(PDWORD(lpinfo) + 9);

	// ctime
	dwtime = *(PDWORD(lpinfo) + 17);
	
	// seq
	dwseq = *(PDWORD(lpinfo) + 18);

	// id
	psrvid = PLARGE_INTEGER(PDWORD(lpinfo) + 18);
	

	// String �ṹ msg
	PDWORD tmp = PDWORD(*(PDWORD(*(PDWORD(lpinfo) + 11)) + 1));
	if (*(PDWORD(tmp) + 5) >= 0x10)
	{
		lpMsg = *((LPSTR*)(tmp));
	}
	else
	{
		lpMsg = (LPSTR)tmp;
	}

	CString strMsg = CA2W(lpMsg, CP_UTF8);

	// MyAtlTraceA("[%s] ���� Out......  \n", __FUNCTION__);
	MyAtlTraceW(L"[%s] ��� lpFromsztalker is %s, dwMsgType is %d, time is %d, msgseq is %d, srvid is %lld, lpMsg is %s \n", 
		__FUNCTIONW__, strFromsztalker, dwMsgType, dwtime, dwseq, psrvid->QuadPart, strMsg);

	return;
}


// Hook��ĺ���
VOID __stdcall HbParseMsg()
{
    // Pre
	__asm
	{	
		PUSHAD;
		sub esp, 20;
	}
	
	__asm
	{
		push eax;   // size
		push edx;   // buffer
		call DUMPSqliteKey;
	}

	// End
	__asm
	{
		add esp, 20;
		POPAD;	
	}

	return 	RelTxParseMsg();
}


VOID __stdcall HbParseMsgX()
{
	// Pre
	__asm
	{
		PUSHAD;
		sub esp, 20;
	}

	__asm
	{
		push ecx;   // ָ��
		call DUMPDataBase;
	}

	// End
	__asm
	{
		add esp, 20;
		POPAD;
	}

	return 	RelTxParseMsgX();
}


VOID __stdcall HbParseMsgX2()
{
	// Pre
	__asm
	{
		PUSHAD;
		sub esp, 20;
	}

	__asm
	{
		lea ecx, [ebp - 0x70]
		push ecx;   // ָ��
		call ParseMMmsg;
	}

	// End
	__asm
	{
		add esp, 20;
		POPAD;
	}

	return 	RelTxParseMsgX2();
}



#define UPDATEINFO "UPDATE ChatCRMsg SET MsgSvrID = ?3,type = ?4,statusEx = ?6,FlagEx = ?7,Status = ?9,strContent = ?12,bytesTrans = ?15,bytesExtra = ?16 WHERE localId = ?1"
int Hbsqlite3Step(PVOID p)
{

	//
	if (p)
	{
		char* sqltxt = (char*)(*((DWORD*)((PBYTE)(p)+0xb0)));

		// �ܶ�log
		// MyAtlTraceA("sql info is %s", sqltxt);
		if (sqltxt)
		{
			if (strcmpi(sqltxt, UPDATEINFO) == 0)
			{
				MyAtlTraceA("sql info is %s", sqltxt);
			}
		}
	}
	

	return RelWechatsqlite3Step(p);
}



DWORD GetDllCodeSectionSize(HMODULE hDllBase, LPDWORD pBaseOfCode)
{
    DWORD dwCodeSize = 0;
    do
    {
        HMODULE hModule = hDllBase;
        if (!hModule)
            break;

        PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)hModule;
        if (hModule == NULL)
        {
            break;
        }
        __try
        {
            if (pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            {
                break;
            }

            PIMAGE_NT_HEADERS pNtHeader = (PIMAGE_NT_HEADERS)((PBYTE)pDosHeader + pDosHeader->e_lfanew);
            if (pNtHeader->Signature != IMAGE_NT_SIGNATURE)
            {
                break;
            }

            if (pNtHeader->FileHeader.SizeOfOptionalHeader == 0)
            {
                break;
            }

            dwCodeSize = pNtHeader->OptionalHeader.SizeOfCode;

            if (pBaseOfCode)
            {
                *pBaseOfCode = pNtHeader->OptionalHeader.BaseOfCode;
            }

        }
        __except (EXCEPTION_EXECUTE_HANDLER)
        {
            return dwCodeSize;
        }

    } while (FALSE);

    return dwCodeSize;
}


VOID TuckMsg::Start()
{  
	// ��һЩ�ж�
	WCHAR lpFilename[MAX_PATH] = {};
	GetModuleFileName(NULL, lpFilename, MAX_PATH);
	GetPEVersion(lpFilename, &m_exe_msver, &m_exe_lsver);

	// ���̹���
	CString csFileName = CString(PathFindFileName(lpFilename));
	MyAtlTraceW(L"[%s] Filename is %s \n", __FUNCTIONW__, csFileName.GetString());

	if (0 != csFileName.CompareNoCase(L"WeChat.exe"))
	{
		MyAtlTraceW(L"[%s] ����΢�ŵĽ���;�������� \n", __FUNCTIONW__);
		return;
	}

	//// �汾������ ��2.4.5.1
	//if (!(MAKELONG(4, 2) == m_exe_msver && MAKELONG(1, 5) == m_exe_lsver))
	//{
	//	MyAtlTraceW(L"[%s] ��֧�ֵ�΢�Ű汾;�������� \n", __FUNCTIONW__);
	//	return;
	//}

	//  

	m_cs_filename = CString(lpFilename);
	BOOL bfIND = FALSE;
	
	for (int i = 0; i < 10; i++)
	{
		m_hProcess = GetModuleHandle(L"wechatwin.dll");
		if (m_hProcess)
		{
			bfIND = TRUE;
			break;
		}
		else
		{
			Sleep(200);
		}
	}

	if (!bfIND)
	{
		MyAtlTraceW(L"[%s] 2s��û���ҵ� wechatwin.dll \n", __FUNCTIONW__ );
		return;
	}
	
	MyAtlTraceW(L"[%s] wechatwinģ���ַ��%0x \n", __FUNCTIONW__, DWORD(m_hProcess));
	
	_StartImpl();
}


static BOOL PatchMemoryUCHAR(
	__in const PVOID pAddr,
	__in const UCHAR uChar)
{
	DWORD dwOldProtect = 0;
	BOOL bRetVal = FALSE;

	if (VirtualProtect(pAddr, sizeof(ULONG), PAGE_EXECUTE_READWRITE, &dwOldProtect))
	{
		*(PUCHAR)pAddr = uChar;
		bRetVal = VirtualProtect(pAddr, sizeof(ULONG), dwOldProtect, &dwOldProtect);
	}

	return bRetVal;
}


VOID TuckMsg::_StartImpl()
{
    MyAtlTraceW(L"[%s] ��ʼ������......\n", __FUNCTIONW__);

    DWORD dwBaseOfCode = 0;
    DWORD CodeSectionSize = GetDllCodeSectionSize((HMODULE)m_hProcess, &dwBaseOfCode);

	// ���ﻻ�������������㷨
	UCHAR SigPattern[] = "\x55\x8B\xEC\x51\x53\x56\x8B\xF1\x8B\xDA\x85\xF6\x74\x29\x85\xDB\x74\x25\x83\x7D\x08\x00\x74\x1F\xBA";
    PVOID uPos = FindTarget((PVOID)((ULONG_PTR)m_hProcess + dwBaseOfCode), CodeSectionSize, (PUCHAR)SigPattern, 25);

	UCHAR SigPatternX[] = "\x55\x8B\xEC\x83\xE4\xF8\x83\xEC\x44\xA1\xCB\xCB\xCB\xCB\x33\xC4\x89\x44\x24\x40\x8B\xC2\x89\x4C\x24\x14\x8B\x4D\x0C\x53\x56\x57";
	PVOID uPosX = FindTarget((PVOID)((ULONG_PTR)m_hProcess + dwBaseOfCode), CodeSectionSize, (PUCHAR)SigPatternX, 32);

	UCHAR SigPatternXX[35] = {
		0x89, 0x85, 0xF4, 0xFD, 0xFF, 0xFF, 0x8B, 0x45, 0x98, 0x89, 0x95, 0xF8, 0xFD, 0xFF, 0xFF, 0x83,
		0xE0, 0x40, 0xC7, 0x85, 0x2C, 0xFE, 0xFF, 0xFF, 0x02, 0x00, 0x00, 0x00, 0x80, 0x7D, 0xF2, 0x00,
		0x89, 0x45, 0x98
	};
	PVOID uPosXX = FindTarget((PVOID)((ULONG_PTR)m_hProcess + dwBaseOfCode), CodeSectionSize, (PUCHAR)SigPatternXX, 35);

	UCHAR SigPatternXX1[5] = {
		0x84, 0xC9, 0x74, 0x14, 0xE8
	};
	
	PVOID uPosXX1 = FindTarget((PVOID)((ULONG_PTR)m_hProcess + dwBaseOfCode), CodeSectionSize, (PUCHAR)SigPatternXX1, 5);


	UCHAR SigPatternXXX[] = "\x6a\x09\x83\xe0\x20\xC7\x85\x70\xF6\xFF\xFF\x02\x00\x00\x00\x6a\x00\x83\xE0\x40";
	PVOID uPosXXX = FindTarget((PVOID)((ULONG_PTR)m_hProcess + dwBaseOfCode), CodeSectionSize, (PUCHAR)SigPatternXXX, 20);

	UCHAR SigPatternXXXX[] = 
	{
		0x55, 0x8b, 0xec, 0x83, 0xe4, 0xf8, 0x83, 0xec, 0x0c,
		0x53, 0x56, 0x8b, 0x75, 0x08, 0x33, 0xdb, 0xc7, 0x44,
		0x24, 0x08, 0x00, 0x00, 0x00, 0x00
	};
	
	PVOID uPosXXXX = FindTarget((PVOID)((ULONG_PTR)m_hProcess + dwBaseOfCode), CodeSectionSize, (PUCHAR)SigPatternXXXX, 24);

    MyAtlTraceW(L"[%s] uPosλ����%x, uPosXλ����%x, uPosXXλ����%x, uPosXX1λ����%x, uPosXXXλ����%x, uPosXXXXλ����%x\n", __FUNCTIONW__, 
		(ULONG_PTR)uPos, (ULONG_PTR)uPosX, (ULONG_PTR)uPosXX, (ULONG_PTR)uPosXX1, (ULONG_PTR)uPosXXX, (ULONG_PTR)uPosXXXX);

	{
        if (uPos && uPosX && uPosXXX)
        {
            RelTxParseMsg = (TxParseMsg)(DWORD(uPos) + 0);
			RelTxParseMsgX = (TxParseMsgX)(DWORD(uPosX) + 0);
			RelTxParseMsgX2 = (TxParseMsgX2)(DWORD(uPosXXX) + 0);
        }
		if (uPosXXXX)
		{
			RelWechatsqlite3Step = (Wechatsqlite3Step)(DWORD(uPosXXXX) + 0);
		}
        m_Init = TRUE;
	}

	if(uPosXX)
	{
		PatchMemoryUCHAR(PVOID((ULONG_PTR)uPosXX + 35), 0x75);
	}
	
	if (uPosXX1)
	{
		PatchMemoryUCHAR(PVOID((ULONG_PTR)uPosXX1 + 2), 0xEB);
	}

	if (m_Init)
	{
		// ��ʼִ��Hook
		StartHook();
	}
}


VOID TuckMsg::StartHook()
{
    if (RelTxParseMsg)
    {
        if (!Mhook_SetHook((PVOID*)&RelTxParseMsg, HbParseMsg))
        {
            return;
        }
    }

	if (RelTxParseMsgX)
	{
		if (!Mhook_SetHook((PVOID*)&RelTxParseMsgX, HbParseMsgX))
		{
			return;
		}
	}

	if (RelTxParseMsgX2)
	{
		if (!Mhook_SetHook((PVOID*)&RelTxParseMsgX2, HbParseMsgX2))
		{
			return;
		}
	}

	if (RelWechatsqlite3Step)
	{
		if (!Mhook_SetHook((PVOID*)&RelWechatsqlite3Step, Hbsqlite3Step))
		{
			return;
		}
	}
	
	g_DbSleepEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
	
	// ����һ����̨�߳̽������ݵĽ���
	CreateThread(NULL, 0, DecryptDBStart, NULL, 0, NULL);
}
