#include "zpCompressedFile.h"
#include "zpPackage.h"
#include <cassert>
#include "zlib.h"
//#include "PerfUtil.h"

namespace zp
{

////////////////////////////////////////////////////////////////////////////////////////////////////
CompressedFile::CompressedFile(const Package* package, u64 offset, u32 compressedSize, u32 originSize,
								u32 chunkSize, u32 flag, u64 nameHash)
	: m_package(package)
	, m_offset(offset)
	, m_chunkSize(chunkSize)
	, m_flag(flag)
	, m_compressedSize(compressedSize)
	, m_originSize(originSize)
	, m_nameHash(nameHash)
	, m_readPos(0)
	, m_chunkPos(NULL)
	, m_fileData(NULL)
	, m_chunkData(NULL)
{
	assert(package != NULL);
	assert(package->m_stream != NULL);

	if (compressedSize <= 0)
	{
		m_originSize = 0;
	}
	assert(m_chunkSize != 0);
	m_chunkCount = (m_originSize + m_chunkSize - 1) / m_chunkSize;
	//no chunk size array for files have only 1 chunk
	if (m_chunkCount <= 1)
	{
		return;
	}

	//获取文件大小
	u32 availableSize = m_package->getFileAvailableSize(nameHash);
	if (availableSize < m_chunkCount * sizeof(u32))
	{
		m_flag |= FILE_DELETE;	//文件异常删除
		return;
	}
	//array of pointer to chunk data buffer
	//字节流数据，存储
	m_chunkData = new u8*[m_chunkCount];
	memset(m_chunkData, 0, m_chunkCount * sizeof(u8*));
	
	//raw data position of each chunk
	//每个块的存储的位置
	m_chunkPos = new u32[m_chunkCount];
	seekInPackage(0);

	//获取每一块存储的位置
	fread((char*)m_chunkPos, m_chunkCount * sizeof(u32), 1, m_package->m_stream);

	//检查是否正确
	if (!checkChunkPos())
	{
		//let package delete me
		m_flag |= FILE_DELETE;
	}
}

//析构
////////////////////////////////////////////////////////////////////////////////////////////////////
CompressedFile::~CompressedFile()
{
	if (m_chunkPos != NULL)
	{
		delete[] m_chunkPos;
		m_chunkPos = NULL;
	}
	if (m_chunkData != NULL)
	{
		for (u32 i = 0; i < m_chunkCount; ++i)
		{
			if (m_chunkData[i] != NULL)
			{
				delete[] m_chunkData[i];
			}
		}
		delete[] m_chunkData;
		m_chunkData = NULL;
	}
	if (m_fileData != NULL)
	{
		delete[] m_fileData;
		m_fileData = NULL;
	}
	if (m_package->m_lastSeekFile == this)
	{
		m_package->m_lastSeekFile = NULL;
	}
}

//获取文件原始的大小
////////////////////////////////////////////////////////////////////////////////////////////////////
u32 CompressedFile::size() const
{
	return m_originSize;
}

//暂时不清楚拿来干什么，没有实现任何功能
////////////////////////////////////////////////////////////////////////////////////////////////////
u32 CompressedFile::availableSize() const
{
	PACKAGE_LOCK;

	u32 rawAvailableSize = m_package->getFileAvailableSize(m_nameHash);
	if (rawAvailableSize == m_compressedSize)
	{
		return m_originSize;
	}
	//not finished, convert to origin size
	if (m_chunkCount <= 1)
	{
		return 0;
	}
	if (rawAvailableSize < m_chunkCount * sizeof(u32))
	{
		return 0;
	}
	u32 available = 0;
	for (u32 i = 1; i < m_chunkCount; ++i)
	{
		if (rawAvailableSize > m_chunkPos[i])
		{
			available += m_chunkSize;
		}
	}
	return available;
}

//flag
////////////////////////////////////////////////////////////////////////////////////////////////////
u32 CompressedFile::flag() const
{
	return m_flag;
}

//设置读取文件位置
////////////////////////////////////////////////////////////////////////////////////////////////////
void CompressedFile::seek(u32 pos)
{
	if (pos > m_originSize)
	{
		m_readPos = m_originSize;		
	}
	else
	{
		m_readPos = pos;
	}
}

//返回当前文件读取位置
////////////////////////////////////////////////////////////////////////////////////////////////////
u32 CompressedFile::tell() const
{
	return m_readPos;
}

//读取size大小的位置
////////////////////////////////////////////////////////////////////////////////////////////////////
u32 CompressedFile::read(u8* buffer, u32 size)
{
	PACKAGE_LOCK;

	//BEGIN_PERF("read")

	if (m_readPos + size > m_originSize)
	{
		size = m_originSize - m_readPos;
	}
	if (size == 0)
	{
		return 0;
	}
	if (m_chunkCount == 1)
	{
		size = oneChunkRead(buffer, size);
	}
	else
	{
		//let's do something real!
		u32 startChunk = m_readPos / m_chunkSize;
		u32 endChunk = (m_readPos + size + m_chunkSize - 1) / m_chunkSize;
		u32 dstOffset = 0;
		for (u32 chunkIndex = startChunk; chunkIndex < endChunk; ++chunkIndex)
		{
			u32 readOffset = 0;
			u32 readSize = m_chunkSize;
			if (chunkIndex == startChunk)
			{
				readOffset = m_readPos % m_chunkSize;
			}
			if (chunkIndex == endChunk - 1)
			{
				//last chunk
				readSize = (m_readPos + size) - chunkIndex * m_chunkSize;
			}
			if (!readChunk(chunkIndex, readOffset, readSize, buffer + dstOffset))
			{
				return 0;
			}
			dstOffset += readSize;
		}
	}
	m_readPos += size;

	//END_PERF

	return size;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
bool CompressedFile::checkChunkPos() const
{
	assert(m_chunkCount > 1);
	
	//开头4个字节存储块的数量，后面存储压缩块大小+前面4个字节的值，少了最后一个块的大小
	if (m_chunkPos[0] != sizeof(m_chunkPos[0]) * m_chunkCount)
	{
		return false;
	}
	for (u32 i = 1; i < m_chunkCount; ++i)
	{
		if (m_chunkPos[i] <= m_chunkPos[i - 1])
		{
			return false;
		}
		if (m_chunkPos[i] >= m_compressedSize)
		{
			return false;
		}
	}
	return true;
}

//单块读取大小，当有内容是读取，没有时，则是先读取，然后写入
////////////////////////////////////////////////////////////////////////////////////////////////////
u32 CompressedFile::oneChunkRead(u8* buffer, u32 size)
{
	assert(m_readPos + size <= m_originSize);
	assert(m_compressedSize != m_originSize);

	//cached
	if (m_fileData != NULL)
	{
		memcpy(buffer, m_fileData + m_readPos, size);
		return size;
	}

	//第一次读取

	//设置包的读取指针
	seekInPackage(0);

	u8* dstBuffer = NULL;
	if (m_readPos == 0 && size == m_originSize)
	{
		//读取整个文件时，则不需要读入m_fileData
		//want entire file, no need to cache, just fill user buffer
		dstBuffer = buffer;		//读取整个文件时，直接复制，不要缓存
	}
	else
	{
		m_fileData = new u8[m_originSize];
		dstBuffer = m_fileData;
	}

	u8* compressed = new u8[m_compressedSize];
	fread((char*)compressed, m_compressedSize, 1, m_package->m_stream);

	//解压缩
	u32 dstSize = m_originSize;	//don't want m_originSize to be changed

	// xor 63

	for (int  i = 0; i< m_compressedSize; i++)
	{
		compressed[i] ^= 0x63;
	}

	if (uncompress(dstBuffer, &dstSize, compressed, m_compressedSize) != Z_OK)
	{
		size = 0;
	}
	if (m_fileData != NULL && size > 0)
	{
		memcpy(buffer, m_fileData + m_readPos, size);
	}
	delete[] compressed;
	return size;
}

//多块读取
////////////////////////////////////////////////////////////////////////////////////////////////////
bool CompressedFile::readChunk(u32 chunkIndex, u32 offset, u32 readSize, u8* buffer)
{
	assert(m_chunkData != NULL);

	if (m_chunkData[chunkIndex] != NULL)
	{
		//cached
		memcpy(buffer, m_chunkData[chunkIndex] + offset, readSize);
		return true;
	}

	assert(m_chunkPos != NULL);
	seekInPackage(m_chunkPos[chunkIndex]);

	u32 compressedChunkSize = 0;
	u32 originChunkSize = 0;
	if (chunkIndex + 1 < m_chunkCount)
	{
		compressedChunkSize = m_chunkPos[chunkIndex + 1] - m_chunkPos[chunkIndex];
		originChunkSize = m_chunkSize;
	}
	else
	{
		//last chunk
		compressedChunkSize = m_compressedSize - m_chunkPos[m_chunkCount - 1];
		originChunkSize = m_originSize % m_chunkSize;
	}

	u8* dstBuffer = NULL;
	if (offset == 0 && readSize == originChunkSize)
	{
		//want entire chunk, no need to cache, just fill user buffer
		dstBuffer = buffer;
	}
	else
	{
		m_chunkData[chunkIndex] = new u8[originChunkSize];
		dstBuffer = m_chunkData[chunkIndex];
	}

	if (compressedChunkSize == originChunkSize)
	{
		//this chunk was not compressed at all, read directly to the dstBuffer
		fread((char*)dstBuffer, originChunkSize, 1, m_package->m_stream);
	}
	else
	{
		u8* compressed = new u8[compressedChunkSize];
		fread((char*)compressed, compressedChunkSize, 1, m_package->m_stream);

		int ret = uncompress(dstBuffer, &originChunkSize, compressed, compressedChunkSize);
		delete[] compressed;
		if (ret != Z_OK)
		{
			return false;
		}
	}
	if (m_chunkData[chunkIndex] != NULL)
	{
		memcpy(buffer, m_chunkData[chunkIndex] + offset, readSize);
	}
	return true;
}

////////////////////////////////////////////////////////////////////////////////////////////////////
void CompressedFile::seekInPackage(u32 offset)
{
	fseek(m_package->m_stream, m_offset + offset, SEEK_SET);
	m_package->m_lastSeekFile = this;
}

}
