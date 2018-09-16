#ifndef __ZP_FILE_H__
#define __ZP_FILE_H__

#include "zpack.h"

namespace zp
{

class Package;

//文件未经过压缩读取
class File : public IReadFile
{
public:
	File(const Package* package, u64 offset, u32 size, u32 flag, u64 nameHash);
	~File();

	virtual u32 size() const;

	virtual u32 availableSize() const;

	virtual u32 flag() const;

	virtual void seek(u32 pos);

	virtual u32 tell() const;

	virtual u32 read(u8* buffer, u32 size);

private:
	void seekInPackage();

private:
	u64				m_offset;		//偏移量
	u64				m_nameHash;		//hash
	const Package*	m_package;		//zpk包指针
	u32				m_flag;			//flag
	u32				m_size;			//文件大小
	u32				m_readPos;		//读取位置
};

}

#endif
