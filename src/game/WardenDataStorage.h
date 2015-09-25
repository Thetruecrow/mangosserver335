/*
 * Copyright (C) 2005-2011 MaNGOS <http://getmangos.com/>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

#pragma once

#include <map>
#include <vector>
#include "Auth/BigNumber.h"
#include "Policies/Singleton.h"

struct WardenData
{
    uint8 Type;                     // 'check'
    BigNumber i;                    // 'data'
    uint32 Address;                 // 'address'                    // PROC_CHECK, MEM_CHECK, PAGE_CHECK
    uint8 Length;                   // 'length'                     // PROC_CHECK, MEM_CHECK, PAGE_CHECK
    std::string str;                // 'str'                        // LUA, MPQ, DRIVER
    std::vector<uint8> Result;      // 'result'                     // MEM_CHECK
    std::string Comment;            // 'comment'
};

typedef uint16 ScanId;

class CWardenDataStorage
{
    public:
        ~CWardenDataStorage();

        WardenData *GetWardenDataById(ScanId id) const;

        void Init();

        __inline std::vector<ScanId> &GetNonPlayerScans() { return m_nonPlayerScanIds; };
        __inline std::vector<ScanId> &GetPlayerScans() { return m_playerScanIds; };

    private:
        std::map<ScanId, WardenData *> m_dataMap;
        std::vector<ScanId> m_nonPlayerScanIds;
        std::vector<ScanId> m_playerScanIds;

        ScanId m_maxScanId;
};

#define sWarden MaNGOS::Singleton<CWardenDataStorage>::Instance()
