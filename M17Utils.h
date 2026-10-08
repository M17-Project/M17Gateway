/*
 *   Copyright (C) 2020 by Jonathan Naylor G4KLX
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation; either version 2 of the License, or
 *   (at your option) any later version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 *   You should have received a copy of the GNU General Public License
 *   along with this program; if not, write to the Free Software
 *   Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 */

#if !defined(M17Utils_H)
#define  M17Utils_H

#include <string>
#include <cstdint>

class CM17Utils {
public:
	CM17Utils();
	~CM17Utils();

	static void encodeCallsign(const std::string& callsign, unsigned char* encoded);
	static std::string decodeCallsign(const unsigned char* encoded);

	// The M17 CRC-16 (polynomial 0x5935, initial value 0xFFFF)
	static uint16_t createCRC16(const unsigned char* data, unsigned int length);
	static void addCRC16(unsigned char* data, unsigned int length);

private:
};

#endif
