#ifdef WIN32
#    ifndef WIN32_LEAN_AND_MEAN 
#        define WIN32_LEAN_AND_MEAN
#    endif
#    include <windows.h>
#    ifndef PAGE_SIZE
#        define PAGE_SIZE 0x1000
#    endif
#else
#    include <ntifs.h>
#    ifndef MAX_PATH
#        define MAX_PATH 260
#    endif
#endif

#include <emmintrin.h>
#include "FSearch.h"

// 1、搜索字符串
//    SigPattern = "This is a null terminated string."
//    SigMask = NULL or "xxxxxxxxxxx" or "x?xx????xxx"
//
// 2、搜索代码、函数或数据
//    SigPattern = "\x8B\xCE\xE8\x00\x00\x00\x00\x8B"
//    SigMask = "xxxxxxxx" or "xxx????x"
//
// Mask 中的 ? 可用于模糊匹配，在被搜索代码片段中有动态变化的内容时使用(如指令操作的地址、数据等)
//
// 这里是搜索虚拟内存对应的子函数，物理内存操作方面，各人有各人的方法，与此主题无关就省略了
//

// 参数说明；基址，搜索大小，特征码，匹配码
// 匹配码是指怎么匹配特征码，x代码精确匹配，？代表模糊匹配

// 返回值,返回位置
ULONG FastSearchVirtualMemory(ULONG VirtualAddress, ULONG VirtualLength, PUCHAR SigPattern, PCHAR SigMask)
{
	// SigMask 未指定时自动生成简化调用（如只是想简单搜索字符串）
	CHAR TmpMask[PAGE_SIZE];
	if (SigMask == NULL || SigMask[0] == 0) {
		ULONG SigLen = (ULONG)strlen((PCHAR)SigPattern);
		if (SigLen > PAGE_SIZE - 1) SigLen = PAGE_SIZE - 1;
		memset(TmpMask, 'x', SigLen);
		TmpMask[SigLen] = 0;
		SigMask = TmpMask;
	}

	// 常规变量
	PUCHAR MaxAddress = (PUCHAR)(VirtualAddress + VirtualLength);
	PUCHAR BaseAddress;
	PUCHAR CurrAddress;
	PUCHAR CurrPattern;
	PCHAR CurrMask;
	BOOLEAN CurrEqual;
	register UCHAR CurrUChar;

	// SSE 加速相关变量
	__m128i SigHead = _mm_set1_epi8((CHAR)SigPattern[0]);
	__m128i CurHead, CurComp;
	ULONG MskComp, IdxComp;
	ULONGLONG i, j;

	//
	// 第一层遍历使用 SSE 将逐字节加速为逐 16 字节每次（最终加速 12 倍获益主要来源与此）
	//
	// 第二层子串匹配不能使用 SSE 加速，原因有四
	//     1. SSE 虽为单指令多数据，但单个指令 CPU 周期比常规指令要高
	//
	//     2. 从概率上来说，子串匹配时第一个字节命中失败与 SSE 一次性对比 16 个字节命中失败在概率上几乎相等
	//
	//     3. 根据实验采用 SSE 优化第二层子串匹配将显著降低最终查找速度
	//
	//     4. 理论上，即使 SSE 单条指令与常规指令具有同样的CPU周期，最高也只能加速 16 倍
	//
	for (i = 0; i <= VirtualLength - 16; i += 16)
	{
		CurHead = _mm_loadu_si128((__m128i*)(VirtualAddress + i));
		CurComp = _mm_cmpeq_epi8(SigHead, CurHead);
		MskComp = _mm_movemask_epi8(CurComp);

		BaseAddress = (PUCHAR)(VirtualAddress + i);
		j = 0;
		while (_BitScanForward(&IdxComp, MskComp))
		{
			CurrAddress = BaseAddress + j + IdxComp;
			CurrPattern = SigPattern;
			CurrMask = SigMask;
			for (; CurrAddress <= MaxAddress; CurrAddress++, CurrPattern++, CurrMask++)
			{
				// 因为是暴力搜索整个系统的物理内存，而本函数自身的堆栈区当然也属于整个物理内存的一部分
				// 因此为了避免匹配到参数 SigPattern 本身，对其做了相应过滤操作，如不需要可以自行简化 2 行
				CurrUChar = *CurrPattern;
				// *CurrPattern = CurrUChar + 0x1;
				CurrEqual = (*CurrAddress == CurrUChar);
				// *CurrPattern = CurrUChar;

				if (!CurrEqual) { if (*CurrMask == 'x') break; }
				if (*CurrMask == 0) { return (ULONG)(BaseAddress+ j + IdxComp); }
			}

			++IdxComp;
			MskComp = MskComp >> IdxComp;
			j += IdxComp;
		}
	}

	return 0x0;
}






// 搜索特征函数
PVOID FindTarget(PVOID addr, DWORD len, PUCHAR target, DWORD target_len)
{
    PVOID status = NULL;
    DWORD i = 0, j = 0;
    PUCHAR cur = (PUCHAR)addr;
    PUCHAR target_cur = (PUCHAR)target;
    BOOL bBadPoint = FALSE;

	for (i = 0; i < len; i++)
	{
		for (j = 0; j < target_len && (i + j) < len; j++)
		{
			//判断指针地址是否有效
			if (IsBadReadPtr((const void*)&cur[i + j], 1))
			{
				bBadPoint = TRUE;
				break;
			}

			if (cur[i + j] != target_cur[j] && 0xcb != target_cur[j])
			{
				break;
			}
		}

		if (bBadPoint)
			break;

		if (j == target_len)
		{
			status = &cur[i];
			break;
		}
	}
    return status;
}