#ifndef __ZP_COMPRESSED_FILE_H__
#define __ZP_COMPRESSED_FILE_H__

#include "zpack.h"

namespace zp
{

class Package;

//压缩过文件读取
class CompressedFile : public IReadFile
{
public:
	CompressedFile(const Package* package, u64 offset, u32 compressedSize, u32 originSize,
					u32 chunkSize, u32 flag, u64 nameHash);
	virtual ~CompressedFile();

	//from IFiled
	virtual u32 size() const;

	virtual u32 availableSize() const;

	virtual u32 flag() const;

	virtual void seek(u32 pos);

	virtual u32 tell() const;

	virtual u32 read(u8* buffer, u32 size);

private:
	bool checkChunkPos() const;

	void seekInPackage(u32 offset);
	//当只有一个文件时，读取指定数量的字节
	u32 oneChunkRead(u8* buffer, u32 size);

	bool readChunk(u32 chunkIndex, u32 offset, u32 readSize, u8* buffer);

private:
	u64				m_offset;			//在整个zpk文件中的偏移量
	u64				m_nameHash;			//名字hash
	const Package*	m_package;			//对应的zpk包指针
	u32				m_chunkSize;		//大文件分块处理，256k
	u32				m_flag;				//标记
	u32				m_compressedSize;	//压缩后的大小+块大小*sizeof(u32)
	u32				m_originSize;		//原始大小

	u32				m_readPos;			//当前读取位置
	u32				m_chunkCount;		//多少块
	u32*			m_chunkPos;			//字块数量数组
	u8*				m_fileData;		//available when there's only 1 chunk
	u8**			m_chunkData;	//available when there's more than 1 chunk
};

}

#endif
