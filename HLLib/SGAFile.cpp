/*
 * HLLib
 * Copyright (C) 2006-2012 Ryan Gregg

 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later
 * version.
 */

#include "HLLib.h"
#include "SGAFile.h"
#include "Streams.h"
#include "Checksum.h"
#include "Utility.h"

#if USE_ZLIB
#	ifdef _WIN32
#		define ZLIB_WINAPI
#	endif
#	include <zlib.h>
#endif

using namespace HLLib;

#define HL_SGA_CHECKSUM_LENGTH 0x00008000

const char *CSGAFile::lpAttributeNames[] = { "Major Version", "Minor Version", "File MD5", "Name", "Header MD5" };
const char *CSGAFile::lpItemAttributeNames[] = { "Section Alias", "Section Name", "Modified", "Type", "CRC" };

CSGAFile::CSGAFile() : CPackage(), pHeaderView(0), pHeader(0), pDirectory(0)
{
	
}

CSGAFile::~CSGAFile()
{
	this->Close();
}

HLPackageType CSGAFile::GetType() const
{
	return HL_PACKAGE_SGA;
}

const hlChar *CSGAFile::GetExtension() const
{
	return "sga";
}

const hlChar *CSGAFile::GetDescription() const
{
	return "Archive File";
}

hlBool CSGAFile::MapDataStructures()
{
	if(sizeof(SGAHeader) > this->pMapping->GetMappingSize())
	{
		LastError.SetErrorMessage("Invalid file: the file map is too small for it's header.");
		return hlFalse;
	}

	if(!this->pMapping->Map(this->pHeaderView, 0, sizeof(SGAHeader)))
	{
		return hlFalse;
	}
	this->pHeader = static_cast<const SGAHeader *>(this->pHeaderView->GetView());

	if(memcmp(this->pHeader->lpSignature, "_ARCHIVE", 8) != 0)
	{
		LastError.SetErrorMessage("Invalid file: the file's signature does not match.");
		return hlFalse;
	}

	if((this->pHeader->uiMajorVersion != 4 || this->pHeader->uiMinorVersion != 0) && (this->pHeader->uiMajorVersion != 5 || this->pHeader->uiMinorVersion != 0))
	{
		LastError.SetErrorMessageFormated("Invalid SGA version (v%hu.%hu): you have a version of a SGA file that HLLib does not know how to read. Check for product updates.", this->pHeader->uiMajorVersion, this->pHeader->uiMinorVersion);
		return hlFalse;
	}

	if(this->pHeader->uiHeaderLength > this->pMapping->GetMappingSize())
	{
		LastError.SetErrorMessage("Invalid file: the file map is too small for it's extended header.");
		return hlFalse;
	}

	switch(this->pHeader->uiMajorVersion)
	{
	case 4:
		this->pDirectory = new CSGADirectory4(*this);
		break;
	case 5:
		this->pDirectory = new CSGADirectory5(*this);
		break;
	default:
		assert(false);
		return hlFalse;
	}

	if(!this->pDirectory->MapDataStructures())
	{
		return hlFalse;
	}

	return hlTrue;
}

hlVoid CSGAFile::UnmapDataStructures()
{
	delete this->pDirectory;
	this->pDirectory = 0;

	this->pHeader = 0;

	this->pMapping->Unmap(this->pHeaderView);
}

CDirectoryFolder *CSGAFile::CreateRoot()
{
	return this->pDirectory->CreateRoot();
}

hlBool CSGAFile::GetItemAttributeInternal(const CDirectoryItem *pItem, HLPackageAttribute eAttribute, HLAttribute &Attribute) const
{
	return this->pDirectory->GetItemAttributeInternal(pItem, eAttribute, Attribute);
}

hlBool CSGAFile::GetFileExtractableInternal(const CDirectoryFile *pFile, hlBool &bExtractable) const
{
	return this->pDirectory->GetFileExtractableInternal(pFile, bExtractable);
}

hlBool CSGAFile::GetFileValidationInternal(const CDirectoryFile *pFile, HLValidation &eValidation) const
{
	return this->pDirectory->GetFileValidationInternal(pFile, eValidation);
}

hlBool CSGAFile::GetFileSizeInternal(const CDirectoryFile *pFile, hlUInt &uiSize) const
{
	return this->pDirectory->GetFileSizeInternal(pFile, uiSize);
}

hlBool CSGAFile::GetFileSizeOnDiskInternal(const CDirectoryFile *pFile, hlUInt &uiSize) const
{
	return this->pDirectory->GetFileSizeOnDiskInternal(pFile, uiSize);
}

hlBool CSGAFile::CreateStreamInternal(const CDirectoryFile *pFile, Streams::IStream *&pStream) const
{
	return this->pDirectory->CreateStreamInternal(pFile, pStream);
}

hlVoid CSGAFile::ReleaseStreamInternal(Streams::IStream &Stream) const
{
	return this->pDirectory->ReleaseStreamInternal(Stream);
}


hlUInt CSGAFile::GetAttributeCountInternal() const
{
	return HL_SGA_PACKAGE_COUNT;
}

const hlChar *CSGAFile::GetAttributeNameInternal(HLPackageAttribute eAttribute) const
{
	if(eAttribute < HL_SGA_PACKAGE_COUNT)
	{
		return this->lpAttributeNames[eAttribute];
	}

	return 0;
}

hlBool CSGAFile::GetAttributeInternal(HLPackageAttribute eAttribute, HLAttribute &Attribute) const
{
	hlChar lpBuffer[64];
	switch(eAttribute)
	{
	case HL_SGA_PACKAGE_VERSION_MAJOR:
		hlAttributeSetUnsignedInteger(&Attribute, this->lpAttributeNames[eAttribute], this->pHeader->uiMajorVersion, hlFalse);
		return hlTrue;
	case HL_SGA_PACKAGE_VERSION_MINOR:
		hlAttributeSetUnsignedInteger(&Attribute, this->lpAttributeNames[eAttribute], this->pHeader->uiMinorVersion, hlFalse);
		return hlTrue;
	case HL_SGA_PACKAGE_MD5_FILE:
		BufferToHexString(this->pHeader->lpFileMD5, 16, lpBuffer, sizeof(lpBuffer));
		hlAttributeSetString(&Attribute, this->lpAttributeNames[eAttribute], lpBuffer);
		return hlTrue;
	case HL_SGA_PACKAGE_NAME:
		WStringToString(this->pHeader->lpName, lpBuffer, sizeof(lpBuffer));
		hlAttributeSetString(&Attribute, this->lpAttributeNames[eAttribute], lpBuffer);
		return hlTrue;
	case HL_SGA_PACKAGE_MD5_HEADER:
		BufferToHexString(this->pHeader->lpHeaderMD5, 16, lpBuffer, sizeof(lpBuffer));
		hlAttributeSetString(&Attribute, this->lpAttributeNames[eAttribute], lpBuffer);
		return hlTrue;
	default:
		return hlFalse;
	}
}

hlUInt CSGAFile::GetItemAttributeCountInternal() const
{
	return HL_SGA_ITEM_COUNT;
}

const hlChar *CSGAFile::GetItemAttributeNameInternal(HLPackageAttribute eAttribute) const
{
	if(eAttribute < HL_SGA_ITEM_COUNT)
	{
		return this->lpItemAttributeNames[eAttribute];
	}

	return 0;
}

CSGAFile::ISGADirectory::~ISGADirectory()
{

}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::CSGADirectory(CSGAFile& File) : File(File), pHeaderDirectoryView(0), pDirectoryHeader(0), lpSections(0), lpFolders(0), lpFiles(0), lpStringTable(0)
{

}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::~CSGADirectory()
{
	this->UnmapDataStructures();
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlBool CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::MapDataStructures()
{
	if(!this->File.pMapping->Map(this->pHeaderDirectoryView, sizeof(SGAHeader), this->File.pHeader->uiHeaderLength))
	{
		return hlFalse;
	}

	this->pDirectoryHeader = static_cast<const TSGADirectoryHeader *>(this->pHeaderDirectoryView->GetView());

	if(this->pDirectoryHeader->uiSectionCount > 0 && this->pDirectoryHeader->uiSectionOffset + sizeof(TSGASection) * this->pDirectoryHeader->uiSectionCount > this->File.pHeader->uiHeaderLength)
	{
		LastError.SetErrorMessage("Invalid file: the file map is too small for section data.");
		return hlFalse;
	}
	if(this->pDirectoryHeader->uiFolderCount > 0 && this->pDirectoryHeader->uiFolderOffset + sizeof(TSGAFolder) * this->pDirectoryHeader->uiFolderCount > this->File.pHeader->uiHeaderLength)
	{
		LastError.SetErrorMessage("Invalid file: the file map is too small for folder data.");
		return hlFalse;
	}
	if(this->pDirectoryHeader->uiFileCount > 0 && this->pDirectoryHeader->uiFileOffset + sizeof(TSGAFile) * this->pDirectoryHeader->uiFileCount > this->File.pHeader->uiHeaderLength)
	{
		LastError.SetErrorMessage("Invalid file: the file map is too small for file data.");
		return hlFalse;
	}
	if(this->pDirectoryHeader->uiStringTableOffset > this->File.pHeader->uiHeaderLength)
	{
		LastError.SetErrorMessage("Invalid file: the file map is too small for string table data.");
		return hlFalse;
	}

	this->lpSections = reinterpret_cast<const TSGASection *>(reinterpret_cast<const hlByte *>(this->pDirectoryHeader) + this->pDirectoryHeader->uiSectionOffset);
	this->lpFolders = reinterpret_cast<const TSGAFolder *>(reinterpret_cast<const hlByte *>(this->pDirectoryHeader) + this->pDirectoryHeader->uiFolderOffset);
	this->lpFiles = reinterpret_cast<const TSGAFile *>(reinterpret_cast<const hlByte *>(this->pDirectoryHeader) + this->pDirectoryHeader->uiFileOffset);
	this->lpStringTable = reinterpret_cast<const hlChar *>(reinterpret_cast<const hlByte *>(this->pDirectoryHeader) + this->pDirectoryHeader->uiStringTableOffset);

	return hlTrue;
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlVoid CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::UnmapDataStructures()
{
	this->pDirectoryHeader = 0;
	this->lpSections = 0;
	this->lpFolders = 0;
	this->lpFiles = 0;
	this->lpStringTable = 0;

	this->File.pMapping->Unmap(this->pHeaderDirectoryView);
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
CDirectoryFolder *CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::CreateRoot()
{
	CDirectoryFolder *pRoot = new CDirectoryFolder(&File);

	for(hlUInt i = 0; i < this->pDirectoryHeader->uiSectionCount; i++)
	{
		CDirectoryFolder* pSection;
		// Check if folder exists.
		CDirectoryItem *pItem = pRoot->GetItem(this->lpSections[i].lpAlias);
		if(pItem == 0 || pItem->GetType() == HL_ITEM_FILE)
		{
			// It doesn't, create it.
			pSection = pRoot->AddFolder(this->lpSections[i].lpAlias);
		}
		else
		{
			// It does, use it.
			pSection = static_cast<CDirectoryFolder *>(pItem);
		}
		this->CreateFolder(pSection, this->lpSections[i].uiFolderRootIndex);
	}

	return pRoot;
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlVoid CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::CreateFolder(CDirectoryFolder *pParent, hlUInt uiFolderIndex)
{
	const hlChar* lpName = this->lpStringTable + this->lpFolders[uiFolderIndex].uiNameOffset;
	if(*lpName != '\0')
	{
		// Strip parent folder names.
		const hlChar* lpTemp = strrchr(lpName, '/');
		if(lpTemp != 0)
		{
			lpName = lpTemp + 1;
		}
		lpTemp = strrchr(lpName, '\\');
		if(lpTemp != 0)
		{
			lpName = lpTemp + 1;
		}
		// Check if folder exists.
		CDirectoryItem *pItem = pParent->GetItem(lpName);
		if(pItem == 0 || pItem->GetType() == HL_ITEM_FILE)
		{
			// It doesn't, create it.
			pParent = pParent->AddFolder(lpName);
		}
		else
		{
			// It does, use it.
			pParent = static_cast<CDirectoryFolder *>(pItem);
		}
	}
	for(hlUInt i = this->lpFolders[uiFolderIndex].uiFolderStartIndex; i < this->lpFolders[uiFolderIndex].uiFolderEndIndex; i++)
	{
		CreateFolder(pParent, i);
	}
	for(hlUInt i = this->lpFolders[uiFolderIndex].uiFileStartIndex; i < this->lpFolders[uiFolderIndex].uiFileEndIndex; i++)
	{
		const hlChar* lpName = this->lpStringTable + this->lpFiles[i].uiNameOffset;
		pParent->AddFile(lpName, i);
	}
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlBool CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::GetItemAttributeInternal(const CDirectoryItem *pItem, HLPackageAttribute eAttribute, HLAttribute &Attribute) const
{
	if(pItem->GetID() != HL_ID_INVALID)
	{
		switch(pItem->GetType())
		{
			case HL_ITEM_FOLDER:
			{
				const CDirectoryFolder *pFolder = static_cast<const CDirectoryFolder *>(pItem);
				switch(eAttribute)
				{
					case HL_SGA_ITEM_SECTION_ALIAS:
					{
						for(hlUInt i = 0; i < this->pDirectoryHeader->uiSectionCount; i++)
						{
							if(pFolder->GetID() >= this->lpSections[i].uiFolderStartIndex && pFolder->GetID() < this->lpSections[i].uiFolderEndIndex)
							{
								hlAttributeSetString(&Attribute, CSGAFile::lpItemAttributeNames[eAttribute], this->lpSections[i].lpAlias);
								return hlTrue;
							}
						}
						return hlFalse;
					}
					case HL_SGA_ITEM_SECTION_NAME:
					{
						for(hlUInt i = 0; i < this->pDirectoryHeader->uiSectionCount; i++)
						{
							if(pFolder->GetID() >= this->lpSections[i].uiFolderStartIndex && pFolder->GetID() < this->lpSections[i].uiFolderEndIndex)
							{
								hlAttributeSetString(&Attribute, CSGAFile::lpItemAttributeNames[eAttribute], this->lpSections[i].lpName);
								return hlTrue;
							}
						}
						return hlFalse;
					}
				}
				break;
			}
			case HL_ITEM_FILE:
			{
				const CDirectoryFile *pFile = static_cast<const CDirectoryFile *>(pItem);
				const TSGAFile &File = this->lpFiles[pFile->GetID()];
				switch(eAttribute)
				{
					case HL_SGA_ITEM_SECTION_ALIAS:
					{
						for(hlUInt i = 0; i < this->pDirectoryHeader->uiSectionCount; i++)
						{
							if(pFile->GetID() >= this->lpSections[i].uiFileStartIndex && pFile->GetID() < this->lpSections[i].uiFileEndIndex)
							{
								hlAttributeSetString(&Attribute, CSGAFile::lpItemAttributeNames[eAttribute], this->lpSections[i].lpAlias);
								return hlTrue;
							}
						}
						return hlFalse;
					}
					case HL_SGA_ITEM_SECTION_NAME:
					{
						for(hlUInt i = 0; i < this->pDirectoryHeader->uiSectionCount; i++)
						{
							if(pFile->GetID() >= this->lpSections[i].uiFileStartIndex && pFile->GetID() < this->lpSections[i].uiFileEndIndex)
							{
								hlAttributeSetString(&Attribute, CSGAFile::lpItemAttributeNames[eAttribute], this->lpSections[i].lpName);
								return hlTrue;
							}
						}
						return hlFalse;
					}
					case HL_SGA_ITEM_MODIFIED:
					{
						time_t Time = (time_t)File.uiTimeModified;
						tm *pTime = localtime(&Time);

						hlChar lpTime[128];
						strftime(lpTime, sizeof(lpTime), "%c", pTime);

						hlAttributeSetString(&Attribute, CSGAFile::lpItemAttributeNames[eAttribute], lpTime);
						return hlTrue;
					}
					case HL_SGA_ITEM_TYPE:
					{
						hlAttributeSetUnsignedInteger(&Attribute, CSGAFile::lpItemAttributeNames[eAttribute], File.uiType, hlFalse);
						return hlTrue;
					}
					case HL_SGA_ITEM_CRC:
					{
						Mapping::CView *pFileHeaderView = 0;
						if(this->File.pMapping->Map(pFileHeaderView, this->File.pHeader->uiFileDataOffset + File.uiOffset - sizeof(TSGAFileHeader), sizeof(TSGAFileHeader)))
						{
							const TSGAFileHeader* pFileHeader = static_cast<const TSGAFileHeader *>(pFileHeaderView->GetView());
							hlAttributeSetUnsignedInteger(&Attribute, CSGAFile::lpItemAttributeNames[eAttribute], pFileHeader->uiCRC32, hlTrue);
							this->File.pMapping->Unmap(pFileHeaderView);
							return hlTrue;
						}
						return hlFalse;
					}
				}
				break;
			}
		}
	}
	return hlFalse;
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlBool CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::GetFileExtractableInternal(const CDirectoryFile *pFile, hlBool &bExtractable) const
{
#if !USE_ZLIB
	const TSGAFile &File = this->lpFiles[pFile->GetID()];

	bExtractable = File.uiType == 0;
#else
	bExtractable = true;
#endif

	return hlTrue;
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlBool CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::GetFileValidationInternal(const CDirectoryFile *pFile, HLValidation &eValidation) const
{
	const TSGAFile &File = this->lpFiles[pFile->GetID()];

#if !USE_ZLIB
	if(File.uiType != 0)
	{
		eValidation = HL_VALIDATES_ASSUMED_OK;
		return hlTrue;
	}
#endif

	Mapping::CView *pFileHeaderDataView = 0;
	if(this->File.pMapping->Map(pFileHeaderDataView, this->File.pHeader->uiFileDataOffset + File.uiOffset - sizeof(TSGAFileHeader), File.uiSizeOnDisk + sizeof(TSGAFileHeader)))
	{
		hlULong uiChecksum = 0;
		const TSGAFileHeader* pFileHeader = static_cast<const TSGAFileHeader*>(pFileHeaderDataView->GetView());
		const hlByte* lpBuffer = reinterpret_cast<const hlByte *>(pFileHeader) + sizeof(TSGAFileHeader);
#if USE_ZLIB
		hlByte *lpInflateBuffer = 0;
		if(File.uiType != 0)
		{
			lpInflateBuffer = new hlByte[File.uiSize];
			uLongf iInflateSize = File.uiSize;
			switch(uncompress(lpInflateBuffer, &iInflateSize, lpBuffer, static_cast<uLong>(File.uiSizeOnDisk)))
			{
			case Z_OK:
				lpBuffer = lpInflateBuffer;
				break;
			default:
				delete []lpInflateBuffer;
				lpInflateBuffer = 0;
				eValidation = HL_VALIDATES_ERROR;
				break;
			}
		}
		if(File.uiType == 0 || lpInflateBuffer != 0)
#endif
		{
			hlULongLong uiTotalBytes = 0, uiFileBytes = File.uiSize;

			hlBool bCancel = hlFalse;
			hlValidateFileProgress(const_cast<CDirectoryFile *>(pFile), uiTotalBytes, uiFileBytes, &bCancel);

			while(uiTotalBytes < uiFileBytes)
			{
				if(bCancel)
				{
					eValidation = HL_VALIDATES_CANCELED;
					break;
				}

				hlUInt uiBufferSize = static_cast<hlUInt>(uiTotalBytes + HL_SGA_CHECKSUM_LENGTH <= uiFileBytes ? HL_SGA_CHECKSUM_LENGTH : uiFileBytes - uiTotalBytes);
				uiChecksum = CRC32(lpBuffer, uiBufferSize, uiChecksum);

				lpBuffer += uiBufferSize;
				uiTotalBytes += static_cast<hlULongLong>(uiBufferSize);

				hlValidateFileProgress(const_cast<CDirectoryFile *>(pFile), uiTotalBytes, uiFileBytes, &bCancel);
			}
		}
#if USE_ZLIB
		delete []lpInflateBuffer;
#endif
		eValidation = static_cast<hlULong>(pFileHeader->uiCRC32) == uiChecksum ? HL_VALIDATES_OK : HL_VALIDATES_CORRUPT;

		this->File.pMapping->Unmap(pFileHeaderDataView);
	}
	else
	{
		eValidation = HL_VALIDATES_ERROR;
	}

	return hlTrue;
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlBool CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::GetFileSizeInternal(const CDirectoryFile *pFile, hlUInt &uiSize) const
{
	const TSGAFile &File = this->lpFiles[pFile->GetID()];

	uiSize = File.uiSize;

	return hlTrue;
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlBool CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::GetFileSizeOnDiskInternal(const CDirectoryFile *pFile, hlUInt &uiSize) const
{
	const TSGAFile &File = this->lpFiles[pFile->GetID()];

	uiSize = File.uiSizeOnDisk;

	return hlTrue;
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlBool CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::CreateStreamInternal(const CDirectoryFile *pFile, Streams::IStream *&pStream) const
{
	const TSGAFile &File = this->lpFiles[pFile->GetID()];

	if(File.uiType == 0)
	{
		pStream = new Streams::CMappingStream(*this->File.pMapping, this->File.pHeader->uiFileDataOffset + File.uiOffset, File.uiSizeOnDisk);
		return hlTrue;
	}
	else
	{
#if USE_ZLIB
		Mapping::CView *pFileDataView = 0;
		if(this->File.pMapping->Map(pFileDataView, this->File.pHeader->uiFileDataOffset + File.uiOffset, File.uiSizeOnDisk))
		{
			hlBool bResult = hlFalse;
			hlByte *lpInflateBuffer = new hlByte[File.uiSize];
			uLongf iInflateSize = File.uiSize;
			switch(uncompress(lpInflateBuffer, &iInflateSize, static_cast<const hlByte *>(pFileDataView->GetView()), (uLong)File.uiSizeOnDisk))
			{
			case Z_OK:
				pStream = new Streams::CMemoryStream(lpInflateBuffer, iInflateSize);
				bResult = hlTrue;
				break;
			case Z_MEM_ERROR:
				delete []lpInflateBuffer;
				LastError.SetErrorMessage("Deflate Error: Z_MEM_ERROR.");
				break;
			case Z_BUF_ERROR:
				delete []lpInflateBuffer;
				LastError.SetErrorMessage("Deflate Error: Z_BUF_ERROR.");
				break;
			case Z_DATA_ERROR:
				delete []lpInflateBuffer;
				LastError.SetErrorMessage("Deflate Error: Z_DATA_ERROR.");
				break;
			default:
				delete []lpInflateBuffer;
				LastError.SetErrorMessage("Deflate Error: Unknown.");
				break;
			}
			this->File.pMapping->Unmap(pFileDataView);
			return bResult;
		}
#endif
		return hlFalse;
	}
}

template<typename TSGADirectoryHeader, typename TSGASection, typename TSGAFolder, typename TSGAFile, typename TSGAFileHeader>
hlVoid CSGAFile::CSGADirectory<TSGADirectoryHeader, TSGASection, TSGAFolder, TSGAFile, TSGAFileHeader>::ReleaseStreamInternal(Streams::IStream &Stream) const
{
	if(Stream.GetType() == HL_STREAM_MEMORY)
	{
		delete []static_cast<const hlByte *>(static_cast<Streams::CMemoryStream &>(Stream).GetBuffer());
	}
}