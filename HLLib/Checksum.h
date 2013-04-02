/*
 * HLLib
 * Copyright (C) 2006-2013 Ryan Gregg

 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your Option) any later
 * version.
 */

#ifndef CHECKSUM_H
#define CHECKSUM_H

#include "stdafx.h"
#include "Error.h"

namespace HLLib
{
	hlULong Adler32(const hlByte *lpBuffer, hlUInt uiBufferSize, hlULong uiAdler32 = 0);
	hlULong CRC32(const hlByte *lpBuffer, hlUInt uiBufferSize, hlULong uiCRC = 0);

	struct MD5Context
	{
		hlULong lpState[4];
		hlULong lpBlock[16];
		hlULong uiLength;
	};

	hlVoid MD5_Initialize(MD5Context& context);
	hlVoid MD5_Update(MD5Context& context, const hlByte *lpBuffer, hlUInt uiBufferSize);
	hlVoid MD5_Finalize(MD5Context& context, hlByte (&lpDigest)[16]);
}

#endif
