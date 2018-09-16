#ifndef __ZP_PACKAGE_H__
#define __ZP_PACKAGE_H__

#include "zpack.h"
#include <string>
#include <vector>
#include "stdio.h"

#include "pthread.h"

namespace zp
{

#if defined (ZP_USE_WCHAR)
#define Remove _wremove
#define Rename _wrename
	typedef std::wistringstream IStringStream;
#else
#define Remove remove
#define Rename rename
	typedef std::istringstream IStringStream;
#endif

	// fix: modify PACKAGE_FILE_SIGN to DXMP
	const u32 PACKAGE_FILE_SIGN = 'wixz';		 //标记，添加进包头
	const u32 CURRENT_VERSION = '0001';			 //版本号

	///////////////////////////////////////////////////////////////////////////////////////////////////
	//zpk包头
	struct PackageHeader
	{
		u32	sign;						//标记
		u32	version;					//版本号
		u32	headerSize;					//包头大小
		u32	fileCount;					//文件数量
		u64	fileEntryOffset;			//文件实体开始存取的位置（压缩过的），文件实体存取在文件前面
		u64 filenameOffset;				//文件名开始存取压缩的位置，文件名存取在最后
		u32	allFileEntrySize;			//压缩过的文件实体字节流总长度（compress）
		u32 allFilenameSize;			//压缩过文件名总长度
		u32 originFilenamesSize;	//filename size before compression 未压缩过的文件名总长度
		u32 chunkSize;				//file compress unit 默认块大小为256k
		u32	flag;					//标准 ：unicode还是多字节，默认为0多字节
		u32 fileEntrySize;			//默认为每个实体的大小
		u32 reserved[18];			//预留数据，暂时没用
	};

	///////////////////////////////////////////////////////////////////////////////////////////////////
	//每个文件标记
	struct FileEntry
	{
		u64	byteOffset;  //每个文件内容的偏移位置
		u64	nameHash;	//每个文件名的hash
		u32	packSize;	//文件内容压缩完的大小或者文件大小size in package(may be compressed)
		u32 originSize;	//文件原始大小
		u32 flag;		//zp::FILE_COMPRESS 表示文件经过压缩 zp::FILE_DELETE 表示文件删除
		u32 chunkSize;	//can be different with chunkSize in package header，暂时等于包头的chunsize具体什么用途不明
		u64 contentHash; //默认为0，具体内容不明
		u32 availableSize;	//一般为文件大小
		u32 reserved;		//暂时没有用途，默认为0
	};

	//包读取
	///////////////////////////////////////////////////////////////////////////////////////////////////
	class Package : public IPackage
	{
		friend class File;
		friend class CompressedFile;
		friend class WriteFile;

	public:
		Package(const Char* filename, bool readonly, bool readFilename);
		~Package();

		//是否有效
		bool valid() const;

		//是否只读
		virtual bool readonly() const;

		//包名
		virtual const Char* packageFilename() const;

		//是否有文件名
		virtual bool hasFile(const Char* filename) const;

		//打开文件
		virtual IReadFile* openFile(const Char* filename);
		//关闭文件
		virtual void closeFile(IReadFile* file);

		//文件数量
		virtual u32 getFileCount() const;
		virtual bool getFileInfo(u32 index, Char* filenameBuffer, u32 filenameBufferSize, u32* fileSize = 0,
			u32* packSize = 0, u32* flag = 0, u32* availableSize = 0, u64* contentHash = 0) const;
		virtual bool getFileInfo(const Char* filename, u32* fileSize = 0, u32* packSize = 0,
			u32* flag = 0, u32* availableSize = 0, u64* contentHash = 0) const;

		//添加文件
		virtual bool addFile(const Char* filename, const Char* exterFilename, u32 fileSize, u32 flag,
			u32* outPackSize = 0, u32* outFlag = 0, u32 chunkSize = 0);
		//创建一个文件
		virtual IWriteFile* createFile(const Char* filename, u32 fileSize, u32 packSize,
			u32 chunkSize = 0, u32 flag = 0, u64 contentHash = 0);
		virtual IWriteFile* openFileToWrite(const Char* filename);
		virtual void closeFile(IWriteFile* file);

		//移除文件
		virtual bool removeFile(const Char* filename);
		virtual bool dirty() const;
		virtual void flush();

		//
		virtual bool defrag(Callback callback, void* callbackParam);

		//暂时没什么用
		virtual u32 getFileUserDataSize() const;
		virtual bool writeFileUserData(const Char* filename, const u8* data, u32 dataLen);
		virtual bool readFileUserData(const Char* filename, u8* data, u32 dataLen);

	private:
		//读取文件头
		bool readHeader();
		//读取文件fileentries
		bool readFileEntries();
		//读取文件名字
		bool readFilenames();

		//移除需要删除的file实体
		void removeDeletedEntries();
		void writeTables(bool avoidOverwrite);

		//建立hash表
		bool buildHashTable();


		int getFileIndex(const Char* filename) const;
		int getFileIndex(u64 nameHash) const;
		u32 insertFileEntry(FileEntry& entry, const Char* filename);
		bool insertFileHash(u64 nameHash, u32 entryIndex);

		//通过str（一般是文件路径）
		u64 stringHash(const Char* str, u32 seed) const;

		void fixHashTable(u32 index);

		//写入zpk
		void writeRawFile(FileEntry& entry, FILE* file);

		//for writing file
		u32 getFileAvailableSize(u64 nameHash) const;
		bool setFileAvailableSize(u64 nameHash, u32 size);

		FileEntry& getFileEntry(u32 index) const;

	private:

		mutable pthread_mutex_t mutex_;

		String					m_packageFilename; //zpk包名
		mutable FILE*			m_stream;		//打开的zpk的指针
		PackageHeader			m_header;		//包头
		u32						m_hashBits;		//hashtable 对应的位数（最小为8--对应hash表数量为2^8-1 =256）
		std::vector<int>		m_hashTable;	//hashtable,实体索引hashtble（index = 实体.namehash&m_hashMask）
		std::vector<u8>			m_fileEntries;	//文件fileEntry的数据
		std::vector<String>		m_filenames;	//文件名数据
		u64						m_packageEnd;	//当前包结尾的偏移位置
		u32						m_hashMask;		//掩码 m_hashMask = (1 << m_hashBits) - 1;
		std::vector<u8>			m_chunkData;
		std::vector<u8>			m_compressBuffer;
		std::vector<u32>		m_chunkPosBuffer;
		mutable void*			m_lastSeekFile;
		bool					m_readonly;
		bool					m_dirty;
	};

	//获取文件数量
	///////////////////////////////////////////////////////////////////////////////////////////////////
	inline u32 Package::getFileCount() const
	{
		//m_header.fileEntrySize 每个文件实体的大小
		return (u32)(m_fileEntries.size() / m_header.fileEntrySize);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	//获取具体的文件实体
	inline FileEntry& Package::getFileEntry(u32 index) const
	{
		return *((FileEntry*)&m_fileEntries[index * m_header.fileEntrySize]);
	}

	////////////////////////////////////////////////////////////////////////////////////////////////////
	class Lock
	{
	public:
		Lock(pthread_mutex_t* mutex) : mutex_(mutex){ pthread_mutex_lock(mutex_); }
		~Lock()	{ pthread_mutex_unlock(mutex_); }
		pthread_mutex_t* mutex_;
	};

#define SCOPE_LOCK		Lock localLock(&mutex_)
#define PACKAGE_LOCK	Lock localLock(&(m_package->mutex_))
};
#endif