#include "zpPackage.h"
#include "zpFile.h"
#include "zpCompressedFile.h"
#include "zpWriteFile.h"
#include "WriteCompressFile.h"
#include "zlib.h"
#include <cassert>
#include <sstream>

//#include "PerfUtil.h"
//#include "windows.h"

//temp
//double g_addFileTime = 0;
//double g_compressTime = 0;

namespace zp
{

const u32 HASH_TABLE_SCALE = 4;
const u32 MIN_HASH_BITS = 8;
const u32 MIN_HASH_TABLE_SIZE = (1<<MIN_HASH_BITS);
const u32 MAX_HASH_TABLE_SIZE = 0x100000;
const u32 MIN_CHUNK_SIZE = 0x1000;

const u32 HASH_SEED = 131;

using namespace std;

///////////////////////////////////////////////////////////////////////////////////////////////////
Package::Package(const Char* filename, bool readonly, bool readFilename)
	: m_stream(NULL)
	, m_hashBits(MIN_HASH_BITS)
	, m_packageEnd(0)
	, m_hashMask(0)
	, m_readonly(readonly)
	, m_lastSeekFile(NULL)
	, m_dirty(false)
{

	pthread_mutex_init(&mutex_, NULL);
	//require filename to modify package
	if (!readFilename && !readonly)
	{
		return;
	}

	//读取文件
	if (readonly)
	{
		m_stream = Fopen(filename, _T("rb"));
	}
	else
	{
		m_stream = Fopen(filename, _T("r+b"));
	}

	if (m_stream == NULL)
	{
		return;
	}

	//读取文件头和文件实体
	if (!readHeader() || !readFileEntries())
	{
		goto Error;
	}
	if (readFilename && !readFilenames())
	{
		goto Error;
	}

	//建立hashtable
	if (!buildHashTable())
	{
		goto Error;
	}
	m_packageFilename = filename;
	if (!readonly)
	{
		//for compress output
		m_compressBuffer.resize(m_header.chunkSize);
		m_chunkData.resize(m_header.chunkSize);
	}
	return;
Error:
	if (m_stream != NULL)
	{
		fclose(m_stream);
		m_stream = NULL;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
Package::~Package()
{
	if (m_stream != NULL)
	{
		removeDeletedEntries();
		flush();
		fclose(m_stream);
	}

	pthread_mutex_destroy(&mutex_);
}

//pack会否有效
///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::valid() const
{
	return (m_stream != NULL);
}

//是否只读
///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::readonly() const
{
	return m_readonly;
}

//包名
///////////////////////////////////////////////////////////////////////////////////////////////////
const Char* Package::packageFilename() const
{
	return m_packageFilename.c_str();
}

//是否有某个名字，通过hash计算
///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::hasFile(const Char* filename) const
{
	SCOPE_LOCK;

	return (getFileIndex(filename) >= 0);
}

//打开其中一个文件。
///////////////////////////////////////////////////////////////////////////////////////////////////
IReadFile* Package::openFile(const Char* filename)
{
	SCOPE_LOCK;

	int fileIndex = getFileIndex(filename);
	if (fileIndex < 0)
	{
		return NULL;
	}
	FileEntry& entry = getFileEntry(fileIndex);
	if ((entry.flag & FILE_COMPRESS) == 0)
	{
		//未压缩
		return new File(this, entry.byteOffset, entry.packSize, entry.flag, entry.nameHash);
	}

	//压缩
	u32 chunkSize = entry.chunkSize == 0 ? m_header.chunkSize : entry.chunkSize;
	CompressedFile* file = new CompressedFile(this, entry.byteOffset, entry.packSize, entry.originSize,
												chunkSize, entry.flag, entry.nameHash);
	if ((file->flag() & FILE_DELETE) != 0)
	{
		delete file;
		file = NULL;
	}
	return file;
}

//关闭该文件
///////////////////////////////////////////////////////////////////////////////////////////////////
void Package::closeFile(IReadFile* file)
{
	SCOPE_LOCK;

	if ((file->flag() & FILE_COMPRESS) == 0)
	{
		delete static_cast<File*>(file);
	}
	else
	{
		delete static_cast<CompressedFile*>(file);
	}
}

//关闭文件
///////////////////////////////////////////////////////////////////////////////////////////////////
void Package::closeFile(IWriteFile* file)
{
	SCOPE_LOCK;

	delete static_cast<WriteFile*>(file);
}

//获取文件信息
///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::getFileInfo(u32 index, Char* filenameBuffer, u32 filenameBufferSize, u32* fileSize,
							u32* packSize, u32* flag, u32* availableSize, u64* contentHash) const
{
	SCOPE_LOCK;

	if (index >= m_filenames.size())
	{
		return false;
	}
	if (filenameBuffer != NULL)
	{
		wcscpy(filenameBuffer, m_filenames[index].c_str());
		filenameBuffer[filenameBufferSize - 1] = 0;
	}
	const FileEntry& entry = getFileEntry(index);
	if (fileSize != NULL)
	{
		*fileSize = entry.originSize;
	}
	if (packSize != NULL)
	{
		*packSize = entry.packSize;
	}
	if (flag != NULL)
	{
		*flag = entry.flag;
	}
	if (availableSize != NULL)
	{
		*availableSize = entry.availableSize;
	}
	if (contentHash != NULL)
	{
		*contentHash = entry.contentHash;
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::getFileInfo(const Char* filename, u32* fileSize, u32* packSize, u32* flag,
						u32* availableSize, u64* contentHash) const
{
	SCOPE_LOCK;

	int fileIndex = getFileIndex(filename);
	if (fileIndex < 0)
	{
		return false;
	}
	const FileEntry& entry = getFileEntry(fileIndex);
	if (fileSize != NULL)
	{
		*fileSize = entry.originSize;
	}
	if (packSize != NULL)
	{
		*packSize = entry.packSize;
	}
	if (flag != NULL)
	{
		*flag = entry.flag;
	}
	if (availableSize != NULL)
	{
		*availableSize = entry.availableSize;
	}
	if (contentHash != NULL)
	{
		*contentHash = entry.contentHash;
	}
	return true;
}

//添加一个文件到包中
///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::addFile(const Char* filename, const Char* externalFilename, u32 fileSize, u32 flag,
						u32* outPackSize, u32* outFlag, u32 chunkSize)
{
	SCOPE_LOCK;

	if (m_readonly)
	{
		return false;
	}
	if (chunkSize == 0)
	{
		chunkSize = m_header.chunkSize;
	}

	//添加文件，externalFilename 全路径文件，filename:单独相对路径名
	FILE* file = Fopen(externalFilename, _T("rb"));
	if (file == NULL)
	{
		return false;
	}

	m_dirty = true;

	//删除文件
	int fileIndex = getFileIndex(filename);
	if (fileIndex >= 0)
	{
		//file exist
		//已经存在一个则，置为可删除
		getFileEntry(fileIndex).flag |= FILE_DELETE;
	}
	//初始化文件实体
	FileEntry entry;
	entry.nameHash = stringHash(filename, HASH_SEED);
	entry.packSize = fileSize;
	entry.originSize = fileSize;
	entry.flag = flag;
	entry.chunkSize = chunkSize;
	entry.contentHash = 0;
	entry.availableSize = fileSize;
	entry.reserved = 0;
	//memset(entry.reserved, 0, sizeof(entry.reserved));

	//插入的位置
	u32 insertedIndex = insertFileEntry(entry, filename);

	if (!insertFileHash(entry.nameHash, insertedIndex))
	{
		//may be hash confliction
		getFileEntry(insertedIndex).flag |= FILE_DELETE;
		return false;
	}
	
	if (fileSize == 0)
	{
		entry.flag &= (~FILE_COMPRESS);
	}
	else
	{
		if ((entry.flag & FILE_COMPRESS) == 0)
		{
			//未压缩直接写入
			writeRawFile(getFileEntry(insertedIndex), file);
		}
		else
		{
			m_chunkData.resize(chunkSize);
			m_compressBuffer.resize(chunkSize);
			FileEntry& dstEntry = getFileEntry(insertedIndex);
			dstEntry.packSize = writeCompressFile(m_stream, entry.byteOffset, file, dstEntry.originSize, chunkSize, dstEntry.flag,
												m_chunkData, m_compressBuffer, m_chunkPosBuffer);
			//temp
			if (m_packageEnd == dstEntry.byteOffset + dstEntry.originSize)
			{
				m_packageEnd = dstEntry.byteOffset + dstEntry.packSize;
			}
		}
	}
	fclose(file);

	if (outPackSize != NULL)
	{
		*outPackSize = getFileEntry(insertedIndex).packSize;
	}
	if (outFlag != NULL)
	{
		*outFlag = getFileEntry(insertedIndex).flag;
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//添加进入zpk，类似于addFile
IWriteFile* Package::createFile(const Char* filename, u32 fileSize, u32 packSize, u32 chunkSize,
								u32 flag, u64 contentHash)
{
	SCOPE_LOCK;

	//只读
	if (m_readonly)
	{
		return NULL;
	}
	m_dirty = true;

	int fileIndex = getFileIndex(filename);
	if (fileIndex >= 0)
	{
		//file exist
		getFileEntry(fileIndex).flag |= FILE_DELETE;
	}

	FileEntry entry;
	entry.nameHash = stringHash(filename, HASH_SEED);
	entry.flag = flag;
	entry.packSize = packSize;
	entry.originSize = fileSize;
	entry.contentHash = contentHash;
	entry.availableSize = 0;
	entry.reserved = 0;
	if ((entry.flag & FILE_COMPRESS) == 0)
	{
		chunkSize = 0;
	}
	entry.chunkSize = chunkSize;
	//memset(entry.reserved, 0, sizeof(entry.reserved));

	u32 insertedIndex = insertFileEntry(entry, filename);

	if (!insertFileHash(entry.nameHash, insertedIndex))
	{
		//hash confliction
		getFileEntry(insertedIndex).flag |= FILE_DELETE;
		return NULL;
	}

	//写入zpk
	return new WriteFile(this, entry.byteOffset, entry.packSize, entry.flag, entry.nameHash);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//打开写入
IWriteFile* Package::openFileToWrite(const Char* filename)
{
	SCOPE_LOCK;

	if (m_readonly)
	{
		return NULL;
	}
	int fileIndex = getFileIndex(filename);
	if (fileIndex < 0)
	{
		return NULL;
	}
	FileEntry& entry = getFileEntry(fileIndex);
	if ((entry.flag & FILE_DELETE) != 0)
	{
		return NULL;
	}
	return new WriteFile(this, entry.byteOffset, entry.packSize, entry.flag, entry.nameHash);
}

//移除文件
///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::removeFile(const Char* filename)
{
	SCOPE_LOCK;

	if (m_readonly)
	{
		return false;
	}
	int fileIndex = getFileIndex(filename);
	if (fileIndex < 0)
	{
		return false;
	}
	//hash table doesn't change until flush，so we shouldn't remove entry here
	getFileEntry(fileIndex).flag |= FILE_DELETE;
	m_dirty = true;
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::dirty() const
{
	return m_dirty;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void Package::flush()
{
	SCOPE_LOCK;

	//m_dirty 修改 m_readonly，只读，只能修改
	if (m_readonly || !m_dirty)
	{
		return;
	}
	m_lastSeekFile = NULL;			//最后修改文件置空

	//写table
	writeTables(true);

	//header
	fseek(m_stream, 0, SEEK_SET);
	fwrite(&m_header, sizeof(m_header), 1, m_stream);

	fflush(m_stream);

	//建立hastable
	buildHashTable();

	//修改
	if (m_header.filenameOffset + m_header.allFilenameSize > m_packageEnd)
	{
		m_packageEnd = m_header.filenameOffset + m_header.allFilenameSize;
	}
	m_dirty = false;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::defrag(Callback callback, void* callbackParam)
{
	SCOPE_LOCK;

	if (m_readonly || m_dirty)
	{
		return false;
	}
	m_lastSeekFile = NULL;

	String tempFilename = m_packageFilename + _T("_");
	FILE* tempFile;
	tempFile = Fopen(tempFilename.c_str(), _T("wb"));
	if (tempFile == NULL)
	{
		return false;
	}
	fseek(tempFile, sizeof(m_header), SEEK_SET);

	vector<char> tempBuffer;
	u64 nextPos = m_header.headerSize;
	//write as chunk instead of file, to speed up
	const u32 MIN_CHUNK_SIZE = 0x100000;
	u64 currentChunkPos = nextPos;
	u64 fragmentSize = 0;
	u32 currentChunkSize = 0;
	u32 fileCount = getFileCount();
	for (u32 i = 0; i < fileCount; ++i)
	{
		FileEntry& entry = getFileEntry(i);
		if (callback != NULL && !callback(m_filenames[i].c_str(), entry.originSize, callbackParam))
		{
			//stop
			fclose(tempFile);
			Remove(tempFilename.c_str());
			return false;
		}
		if (entry.packSize == 0)
		{
			entry.byteOffset = nextPos;
			continue;
		}
		if (entry.byteOffset != fragmentSize + nextPos	//new fragment encountered
			|| currentChunkSize > MIN_CHUNK_SIZE)
		{
			if (currentChunkSize > 0)
			{
				tempBuffer.resize(currentChunkSize);
				fseek(m_stream, currentChunkPos, SEEK_SET);
				fread(&tempBuffer[0], currentChunkSize, 1, m_stream);
				fwrite(&tempBuffer[0], currentChunkSize, 1, tempFile);
			}
			fragmentSize = entry.byteOffset - nextPos;
			currentChunkPos = entry.byteOffset;
			currentChunkSize = 0;
		}
		entry.byteOffset = nextPos;
		nextPos += entry.packSize;
		currentChunkSize += entry.packSize;
	}
	//one chunk may be left
	if (currentChunkSize > 0)
	{
		tempBuffer.resize(currentChunkSize);
		fseek(m_stream, currentChunkPos, SEEK_SET);
		fread(&tempBuffer[0], currentChunkSize, 1, m_stream);
		fwrite(&tempBuffer[0], currentChunkSize, 1, tempFile);
	}

	fclose(m_stream);
	fclose(tempFile);

	m_stream = Fopen(tempFilename.c_str(), _T("r+b"));//ios_base::in | ios_base::out | ios_base::binary);	//only for flush()
	assert(m_stream != NULL);

	//write file entries, filenames and header
	writeTables(false);
	fseek(m_stream, 0, SEEK_SET);
	fwrite(&m_header, sizeof(m_header), 1, m_stream);
	fflush(m_stream);

	fclose(m_stream);

	Remove(m_packageFilename.c_str());
	Rename(tempFilename.c_str(), m_packageFilename.c_str());
	m_stream = Fopen(m_packageFilename.c_str(), _T("r+b"));//ios_base::in | ios_base::out | ios_base::binary);
	assert(m_stream != NULL);
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//玩家自定义数据
u32 Package::getFileUserDataSize() const
{
	assert(m_header.fileEntrySize >= sizeof(FileEntry));
	return m_header.fileEntrySize - sizeof(FileEntry);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::writeFileUserData(const Char* filename, const u8* data, u32 dataLen)
{
	SCOPE_LOCK;

	if (dataLen > getFileUserDataSize())
	{
		return false;
	}
	int fileIndex = getFileIndex(filename);
	if (fileIndex < 0)
	{
		return false;
	}
	FileEntry& entry = getFileEntry(fileIndex);
	memcpy(&entry + 1, data, dataLen);
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::readFileUserData(const Char* filename, u8* data, u32 dataLen)
{
	SCOPE_LOCK;

	if (dataLen > getFileUserDataSize())
	{
		return false;
	}
	int fileIndex = getFileIndex(filename);
	if (fileIndex < 0)
	{
		return false;
	}
	FileEntry& entry = getFileEntry(fileIndex);
	memcpy(data, &entry + 1, dataLen);
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::readHeader()
{
	fseek(m_stream, 0, SEEK_END);
	u64 packageSize = ftell(m_stream);

	//不包含包头
	if (packageSize < sizeof(PackageHeader))
	{
		return false;
	}

	//读取包头验证
	fseek(m_stream, 0, SEEK_SET);
	fread(&m_header, sizeof(PackageHeader), 1, m_stream);

	//这里面没有验证版本，说明版本不同也可以读取文件
	if (m_header.sign != PACKAGE_FILE_SIGN
		|| m_header.headerSize != sizeof(PackageHeader)
		|| m_header.fileEntryOffset < m_header.headerSize
		|| m_header.fileEntryOffset + m_header.allFileEntrySize > packageSize
		|| m_header.filenameOffset < m_header.fileEntryOffset + m_header.allFileEntrySize
		|| m_header.filenameOffset + m_header.allFilenameSize > packageSize
		|| m_header.chunkSize < MIN_CHUNK_SIZE)
	{
		return false;
	}
	if (m_header.version != CURRENT_VERSION && !m_readonly)
	{
		return false;
	}
	if (m_header.fileEntrySize == 0)
	{
		m_header.fileEntrySize = sizeof(FileEntry);
	}
	if (m_header.fileEntrySize < sizeof(FileEntry))
	{
		return false;
	}
	//末尾
	m_packageEnd = m_header.filenameOffset + m_header.allFilenameSize;
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::readFileEntries()
{
	m_fileEntries.resize(m_header.fileCount * m_header.fileEntrySize);
	if (m_header.fileCount == 0)
	{
		return true;
	}
	fseek(m_stream, m_header.fileEntryOffset, SEEK_SET);
	if (m_header.allFileEntrySize == m_header.fileCount * m_header.fileEntrySize)
	{
		//not compressed，
		fread(&m_fileEntries[0], m_header.allFileEntrySize, 1, m_stream);
	}
	else
	{
		vector<u8> srcBuffer(m_header.allFileEntrySize);
		fread(&srcBuffer[0], m_header.allFileEntrySize, 1, m_stream);
		u32 dstBufferSize = m_header.fileCount * m_header.fileEntrySize;
		
		//解压
		int ret = uncompress(&m_fileEntries[0], &dstBufferSize, &srcBuffer[0], m_header.allFileEntrySize);
		if (ret != Z_OK || dstBufferSize != m_header.fileCount * m_header.fileEntrySize)
		{
			return false;
		}
	}
	return true;
}

//读取文件名
///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::readFilenames()
{
	if (m_fileEntries.empty())
	{
		return true;
	}
	if (m_header.allFilenameSize == 0)
	{
		return false;
	}
	fseek(m_stream, m_header.filenameOffset, SEEK_SET);
	vector<u8> dstBuffer(m_header.originFilenamesSize);
	if (m_header.allFilenameSize == m_header.originFilenamesSize)
	{
		//not compressed
		fread(&dstBuffer[0], m_header.allFilenameSize, 1, m_stream);
	}
	else
	{
		vector<u8> tempBuffer(m_header.allFilenameSize);
		fread(&tempBuffer[0], m_header.allFilenameSize, 1, m_stream);
		u32 originSize = m_header.originFilenamesSize;
		int ret = uncompress(&dstBuffer[0], &originSize, &tempBuffer[0], m_header.allFilenameSize);
		if (ret != Z_OK || originSize != m_header.originFilenamesSize)
		{
			return false;
		}
	}
	
	String names;
	names.assign((Char*)&dstBuffer[0], m_header.originFilenamesSize / sizeof(Char));
	
	u32 fileCount = getFileCount();
	m_filenames.resize(fileCount);
	
	IStringStream iss(names, IStringStream::in);
	for (u32 i = 0; i < fileCount; ++i)
	{
		Char out[MAX_FILENAME_LEN];
		iss.getline(out, MAX_FILENAME_LEN);		//每个文件名后面有个回车，去除回车
		m_filenames[i] = out;
	}
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void Package::removeDeletedEntries()
{
	//删除要删除的资料
	if (m_readonly)
	{
		return;
	}
	assert(getFileCount() == m_filenames.size());

	//m_header.fileCount and m_header.allFilenameSize will not change
	vector<String>::iterator nameIter = m_filenames.begin();
	u32 fileCount = getFileCount();
	for (u32 i = 0; i < fileCount;)
	{
		FileEntry& entry = getFileEntry(i);
		if ((entry.flag & FILE_DELETE) != 0)
		{
			std::vector<u8>::iterator eraseBegin = m_fileEntries.begin() + i * m_header.fileEntrySize;
			m_fileEntries.erase(eraseBegin, eraseBegin + m_header.fileEntrySize);
			nameIter = m_filenames.erase(nameIter);
			m_dirty = true;
			--fileCount;
			continue;
		}
		++i;
		++nameIter;
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void Package::writeTables(bool avoidOverwrite)
{
	//空的话
	if (m_fileEntries.empty())
	{
		//nothing to write
		m_header.fileCount = 0;
		m_header.allFileEntrySize = 0;
		m_header.allFilenameSize = 0;
		m_header.fileEntryOffset = sizeof(m_header);
		m_header.filenameOffset = m_header.fileEntryOffset;
		m_header.originFilenamesSize = 0;
		return;
	}

	//compress file entries
	//压缩文件实体
	u32 srcEntrySize = m_fileEntries.size();
	u32 dstEntrySize = srcEntrySize;

	vector<u8> dstEntryBuffer(dstEntrySize);		//压缩进dstEntryBuffer
	int ret = compress(&dstEntryBuffer[0], &dstEntrySize, &m_fileEntries[0], srcEntrySize);
	if (ret != Z_OK || dstEntrySize >= srcEntrySize)
	{
		dstEntrySize = srcEntrySize;		
	}

	//compress filenames
	//压缩文件名
	String srcFilename;
	for (u32 i = 0; i < m_filenames.size(); ++i)
	{
		srcFilename += m_filenames[i];
		srcFilename += _T("\n"); //加入回车
	}

	//文件名长度
	u32 srcFilenameSize = srcFilename.length() * sizeof(Char);
	u32 dstFilenameSize = srcFilenameSize;

	vector<u8> dstFilenameBuffer(dstFilenameSize);
	ret = compress(&dstFilenameBuffer[0], &dstFilenameSize, (const u8*)srcFilename.c_str(), srcFilenameSize);
	if (ret != Z_OK || dstFilenameSize >= srcFilenameSize)
	{
		dstFilenameSize = srcFilenameSize;
	}

	//find pos to write
	u32 lastIndex = getFileCount() - 1;
	FileEntry& last =  getFileEntry(lastIndex);
	u64 lastFileEnd = last.byteOffset + last.packSize;
	//文件末尾
	if (avoidOverwrite)
	{
		if ((lastFileEnd >= m_header.filenameOffset + m_header.allFilenameSize)
			|| (lastFileEnd + dstEntrySize + dstFilenameSize <= m_header.fileEntryOffset))
		{
			m_header.fileEntryOffset = lastFileEnd;
		}
		else
		{
			m_header.fileEntryOffset = m_header.filenameOffset + m_header.allFilenameSize;
		}
	}
	else
	{
		m_header.fileEntryOffset = lastFileEnd;
	}

	//write
	fseek(m_stream, m_header.fileEntryOffset, SEEK_SET);
	if (dstEntrySize == srcEntrySize)
	{
		fwrite(&m_fileEntries[0], srcEntrySize, 1, m_stream);
	}
	else
	{
		fwrite(&dstEntryBuffer[0], dstEntrySize, 1, m_stream);
	}
	if (dstFilenameSize == srcFilenameSize)
	{
		fwrite(&srcFilename[0], srcFilenameSize, 1, m_stream);
	}
	else
	{
		fwrite(&dstFilenameBuffer[0], dstFilenameSize, 1, m_stream);
	}

	m_header.fileCount = getFileCount();
	m_header.allFileEntrySize = dstEntrySize;
	m_header.filenameOffset = m_header.fileEntryOffset + m_header.allFileEntrySize;
	m_header.allFilenameSize = dstFilenameSize;
	m_header.originFilenamesSize = srcFilenameSize;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//重写建立实体，全部清空重写建立实体
bool Package::buildHashTable()
{
	u32 requireSize = getFileCount() * HASH_TABLE_SCALE;
	u32 tableSize = MIN_HASH_TABLE_SIZE;
	m_hashBits = MIN_HASH_BITS;
	while (tableSize < requireSize)
	{
		if (tableSize >= MAX_HASH_TABLE_SIZE)
		{
			return false;
		}
		tableSize *= 2;
		++m_hashBits;
	}
	m_hashMask = (1 << m_hashBits) - 1;

	bool wrong = false;
	m_hashTable.clear();
	m_hashTable.resize(tableSize, -1);		//-1赋值
	u32 fileCount = getFileCount();
	for (u32 i = 0; i < fileCount; ++i)
	{
		const FileEntry& currentEntry = getFileEntry(i);
		u32 index = (currentEntry.nameHash & m_hashMask);
		while (m_hashTable[index] != -1)
		{
			const FileEntry& conflictEntry = getFileEntry(m_hashTable[index]);
			if (!wrong && (conflictEntry.flag & FILE_DELETE) == 0
				&& conflictEntry.nameHash == currentEntry.nameHash)
			{
				wrong = true;
			}
			if (++index >= tableSize)
			{
				index = 0;
			}
		}
		m_hashTable[index] = i;
	}
	return !wrong;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//通过文件名获取在索引，然后获取hashtable值
int Package::getFileIndex(const Char* filename) const
{
	u64 nameHash = stringHash(filename, HASH_SEED);

	return getFileIndex(nameHash);
}

///////////////////////////////////////////////////////////////////////////////////////////////////
int Package::getFileIndex(u64 nameHash) const
{
	u32 hashIndex = (nameHash & m_hashMask);
	int fileIndex = m_hashTable[hashIndex];
	while (fileIndex >= 0)
	{
		const FileEntry& entry = getFileEntry(fileIndex);
		if (entry.nameHash == nameHash)
		{
			if ((entry.flag & FILE_DELETE) != 0)
			{
				return -1;
			}
			return fileIndex;
		}
		if (++hashIndex >= m_hashTable.size())
		{
			hashIndex = 0;
		}
		fileIndex = m_hashTable[hashIndex];
	}
	return -1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
u32 Package::insertFileEntry(FileEntry& entry, const Char* filename)
{
	//删除文件
	u32 maxIndex = getFileCount();
	u64 lastEnd = m_header.headerSize;

	//file with 0 size will alway be put to the end
	for (u32 fileIndex = 0; fileIndex < maxIndex; ++fileIndex)
	{
		FileEntry& thisEntry = getFileEntry(fileIndex);
		//avoid overwritting old file entries and filenames
		if (thisEntry.byteOffset >= lastEnd + entry.packSize
			&& (lastEnd + entry.packSize <= m_header.fileEntryOffset
				|| lastEnd >= m_header.filenameOffset + m_header.allFilenameSize))
		{
			//插入到合适的位置，其他的后移
			entry.byteOffset = lastEnd;

			//清除该位置
			m_fileEntries.insert(m_fileEntries.begin() + fileIndex * m_header.fileEntrySize, m_header.fileEntrySize, 0);
			
			// fix: modify for fix CRASH : if m_fileEntries realloc then thisEntry will be freeed
			// thisEntry = entry;
			//赋值进去
			getFileEntry(fileIndex) = entry; 
			// ###############################
			
			//覆盖
			m_filenames.insert(m_filenames.begin() + fileIndex, filename);
			assert(m_filenames.size() == getFileCount());
			//user may call addFile or removeFile before calling flush, so hash table need to be fixed
			//重写设表值
			fixHashTable(fileIndex);

			return fileIndex;
		}
		lastEnd = thisEntry.byteOffset + thisEntry.packSize;
	}

	if (m_header.fileCount == 0 || m_header.fileEntryOffset > lastEnd + entry.packSize)
	{
		entry.byteOffset = lastEnd;
		if (entry.byteOffset + entry.packSize > m_packageEnd)
		{
			m_packageEnd = entry.byteOffset + entry.packSize;
		}
	}
	else
	{
		entry.byteOffset = m_packageEnd;
		m_packageEnd += entry.packSize;
	}
	m_fileEntries.insert(m_fileEntries.end(), m_header.fileEntrySize, 0);
	u32 newFileCount = getFileCount();
	getFileEntry(newFileCount - 1) = entry;

	m_filenames.push_back(filename);
	assert(m_filenames.size() == newFileCount);
	return m_filenames.size() - 1;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::insertFileHash(u64 nameHash, u32 entryIndex)
{
	u32 requireSize = getFileCount() * HASH_TABLE_SCALE;
	u32 tableSize = m_hashTable.size();
	if (tableSize < requireSize)
	{
		//file entry hash been inserted, just rebuild hash table
		return buildHashTable();
	}
	u32 index = (nameHash & m_hashMask);
	while (m_hashTable[index] != -1)
	{
		const FileEntry& entry = getFileEntry(m_hashTable[index]);
		if ((entry.flag & FILE_DELETE) == 0 && entry.nameHash == nameHash)
		{
			//it's possible that file is added back right after it's deleted
			return false;
		}
		if (++index >= tableSize)
		{
			index = 0;
		}
	}
	m_hashTable[index] = entryIndex;
	return true;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
//计算hash的方法
u64 Package::stringHash(const Char* str, u32 seed) const
{
	u64 out = 0;
	while (*str)
	{
		Char ch = *(str++);
		if (ch == _T('\\'))	//转义符
		{
			ch = _T('/');
		}
	#if (ZP_CASE_SENSITIVE)
		out = out * seed + ch;
	#else
		#if defined ZP_USE_WCHAR
			out = out * seed + towlower(ch);
		#else
			out = out * seed + tolower(ch);
		#endif
	#endif
	}
	return out;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void Package::fixHashTable(u32 index)
{
	//increase file index which is greater than "index" by 1
	for (u32 i = 0; i < m_hashTable.size(); ++i)
	{
		if (m_hashTable[i] >= (int)index)
		{
			++m_hashTable[i];
		}
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
void Package::writeRawFile(FileEntry& entry, FILE* file)
{
	//分块写入一个连续空间
	fseek(m_stream, entry.byteOffset, SEEK_SET);

	u32 chunkCount = (entry.originSize + m_header.chunkSize - 1) / m_header.chunkSize;
	m_chunkData.resize(m_header.chunkSize);
	for (u32 i = 0; i < chunkCount; ++i)
	{
		u32 curChunkSize = m_header.chunkSize;
		if (i == chunkCount - 1 && entry.originSize % m_header.chunkSize != 0)
		{
			curChunkSize = entry.originSize % m_header.chunkSize;
		}
		fread(&m_chunkData[0], curChunkSize, 1, file);
		
		// FIX: 写入位置错误了;
		// fwrite(&m_chunkData[0], curChunkSize, 1, file);
		fwrite(&m_chunkData[0], curChunkSize, 1, m_stream);
	}
}

///////////////////////////////////////////////////////////////////////////////////////////////////
u32 Package::getFileAvailableSize(u64 nameHash) const
{
	int fileIndex = getFileIndex(nameHash);
	if (fileIndex < 0)
	{
		return 0;
	}
	const FileEntry& entry = getFileEntry(fileIndex);
	return entry.availableSize;
}

///////////////////////////////////////////////////////////////////////////////////////////////////
bool Package::setFileAvailableSize(u64 nameHash, u32 size)
{
	int fileIndex = getFileIndex(nameHash);
	if (fileIndex < 0)
	{
		return false;
	}
	FileEntry& entry = getFileEntry(fileIndex);
	entry.availableSize = size;
	m_dirty = true;
	return true;
}

}
