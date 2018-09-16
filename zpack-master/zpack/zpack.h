#ifndef __ZPACK_H__
#define __ZPACK_H__

#include <string>

// #if defined (_MSC_VER) && defined (UNICODE)
// 	#define ZP_USE_WCHAR
// #endif

//#if defined (_MSC_VER)
#define ZP_CASE_SENSITIVE	0
//#else
//	#define ZP_CASE_SENSITIVE	1
//#endif

namespace zp
{
#if defined (ZP_USE_WCHAR)
	typedef wchar_t Char;
	#ifndef _T
		#define _T(str) L##str
	#endif
	typedef std::wstring String;
	#define Fopen _wfopen
	#define Strcpy wcscpy_s
#else
	typedef char Char;
	#ifndef _T
		#define _T(str) str
	#endif
	typedef std::string String;
	#define Fopen fopen
	#define Strcpy strcpy_s
#endif

//其实这功能主要是保证64位机编译，大小不变。。
#ifndef __LP64__
	typedef unsigned char u8;					//1个字节
	typedef unsigned short u16;					//2个字节
	typedef unsigned long u32;					//4个字节
	typedef unsigned long long u64;				//8个字节
#else
	//64位变化的是long和指针大小
	typedef unsigned char u8;					//1个字节
	typedef unsigned short u16;					//2个字节
	typedef unsigned int u32;					//4个字节
	typedef unsigned long long u64;				//8个字节（64位系统大小不变，32位系统也是8字节）
#endif


const u32 MAX_FILENAME_LEN = 1024;

//打开文件模式
const u32 OPEN_READONLY = 1;
const u32 OPEN_NO_FILENAME = 2;

const u32 PACK_UNICODE = 1;

//文件模式flag
const u32 FILE_DELETE = (1<<0);			//删除
const u32 FILE_COMPRESS = (1<<1);		//压缩
//const u32 FILE_WRITING = (1<<2);

const u32 FILE_FLAG_USER0 = (1<<10);	
const u32 FILE_FLAG_USER1 = (1<<11);

typedef bool (*Callback)(const Char* path, zp::u32 fileSize, void* param);

class IReadFile;
class IWriteFile;

///////////////////////////////////////////////////////////////////////////////////////////////////
//zpk包接口
class IPackage
{
public:
	//文件是否只读
	virtual bool readonly() const = 0;
	//包名称
	virtual const Char* packageFilename() const = 0;

	///////////////////////////////////////////////////////////////////////////////////////////////
	//readonly functions, not available when package is dirty
	//IFile will become unavailable after package is modified
	//是否有某个文件。
	virtual bool hasFile(const Char* filename) const = 0;

	//打开文件，其实是从.zpk中找到对应的内容块
	virtual IReadFile* openFile(const Char* filename) = 0;
	//关闭某个文件
	virtual void closeFile(IReadFile* file) = 0;

	//获取中间文件的数量
	virtual u32 getFileCount() const = 0;

	//获取某个文件信息（index/filename）
	virtual bool getFileInfo(u32 index, Char* filenameBuffer, u32 filenameBufferSize, u32* fileSize = 0,
							u32* packSize = 0, u32* flag = 0, u32* availableSize = 0, u64* contentHash = 0) const = 0;
	virtual bool getFileInfo(const Char* filename, u32* fileSize = 0, u32* packSize = 0,
							u32* flag = 0, u32* availableSize = 0, u64* contentHash = 0) const = 0;

	///////////////////////////////////////////////////////////////////////////////////////////////
	//package manipulation fuctions, not available in read only mode

	//do not add same file more than once between flush() call
	//outFileSize	origin file size
	//outPackSize	size in package

	//添加一个文件到zpk中
	virtual bool addFile(const Char* filename, const Char* externalFilename, u32 fileSize, u32 flag,
						u32* outPackSize = 0, u32* outFlag = 0, u32 chunkSize = 0) = 0;
	
	//创建一个文件
	virtual IWriteFile* createFile(const Char* filename, u32 fileSize, u32 packSize,
									u32 chunkSize = 0, u32 flag = 0, u64 contentHash = 0) = 0;

	//打开一个文件写入
	virtual IWriteFile* openFileToWrite(const Char* filename) = 0;
	virtual void closeFile(IWriteFile* file) = 0;

	//can not remove files added after last flush() call
	//删除一个文件
	virtual bool removeFile(const Char* filename) = 0;

	//return true if there's any unsaved change of package
	virtual bool dirty() const = 0;

	//package file won't change before calling this function
	//类似刷新进缓存
	virtual void flush() = 0;

	//暂时不清楚干什么的
	virtual bool defrag(Callback callback, void* callbackParam) = 0;	//can be very slow, don't call this all the time

	virtual u32 getFileUserDataSize() const = 0;

	virtual bool writeFileUserData(const Char* filename, const u8* data, u32 dataLen) = 0;
	virtual bool readFileUserData(const Char* filename, u8* data, u32 dataLen) = 0;

protected:
	virtual ~IPackage(){}
};

///////////////////////////////////////////////////////////////////////////////////////////////////
//读取文件接口，类似FILE接口
class IReadFile
{
public:
	virtual u32 size() const = 0;

	virtual u32 availableSize() const = 0;

	virtual u32 flag() const = 0;

	virtual void seek(u32 pos) = 0;

	virtual u32 tell() const = 0;

	//读取size数据，存进buffer中
	virtual u32 read(u8* buffer, u32 size) = 0;

protected:
	virtual ~IReadFile(){}
};

///////////////////////////////////////////////////////////////////////////////////////////////////
//存文件进入zpk包中
class IWriteFile
{
public:
	virtual u32 size() const = 0;

	virtual u32 flag() const = 0;

	virtual void seek(u32 pos) = 0;

	virtual u32 tell() const = 0;

	virtual u32 write(const u8* buffer, u32 size) = 0;

protected:
	virtual ~IWriteFile(){}
};

///////////////////////////////////////////////////////////////////////////////////////////////////
//创建一个zpk包
IPackage* create(const Char* filename, u32 chunkSize = 0x40000, u32 fileUserDataSize = 0); //2^18 = 256k

//打开一个zpk包
IPackage* open(const Char* filename, u32 flag = OPEN_READONLY | OPEN_NO_FILENAME);

//关闭res.zpk包
void close(IPackage* package);

}

#endif
