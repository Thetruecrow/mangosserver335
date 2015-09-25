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

#include "Common.h"
#include "WorldPacket.h"
#include "WorldSession.h"
#include "Log.h"
#include "ProgressBar.h"
#include "Database/DatabaseEnv.h"
#include "Util.h"
#include "WardenDataStorage.h"
#include "WardenWin.h"

CWardenDataStorage *MaNGOS::Singleton<CWardenDataStorage>::si_instance;
bool MaNGOS::Singleton<CWardenDataStorage>::si_destroyed;

CWardenDataStorage::~CWardenDataStorage()
{
    m_playerScanIds.clear();
    m_nonPlayerScanIds.clear();
    for (std::map<ScanId, WardenData *>::iterator itr = m_dataMap.begin(); itr != m_dataMap.end(); ++itr)
        delete itr->second;
}

void CWardenDataStorage::Init()
{
    QueryResult *result = WorldDatabase.Query("SELECT `id`, `check`, `data`, `str`, `address`, `length`, `result`, `comment` FROM warden_data_result");

    uint32 count = 0;

    if (!result)
    {
        BarGoLink bar(1);
        bar.step();

        sLog.outString();
        sLog.outString(">> Loaded %u warden data and results", count);
        return;
    }

    BarGoLink bar((int)result->GetRowCount());

    for (std::map<ScanId, WardenData *>::iterator itr = m_dataMap.begin(); itr != m_dataMap.end(); ++itr)
        delete itr->second;
    m_dataMap.clear();

    m_playerScanIds.clear();
    m_nonPlayerScanIds.clear();
    m_maxScanId = 0;

    do
    {
        ++count;
        bar.step();

        Field *fields = result->Fetch();

        const ScanId id = (ScanId)fields[0].GetUInt16();
        const uint8 type = fields[1].GetUInt8();

        WardenData *wd = new WardenData();
        wd->Type = type;

        if (type == PLAYER_CHECK)
            m_playerScanIds.push_back(id);
        else m_nonPlayerScanIds.push_back(id);

        if (id > m_maxScanId)
            m_maxScanId = id;

        if (type == PAGE_CHECK_A || type == PAGE_CHECK_B || type == DRIVE_CHECK)
        {
            std::string data = fields[2].GetCppString();
            wd->i.SetHexStr(data.c_str());
            int len = data.size() / 2;
            if (wd->i.GetNumBytes() < len)
            {
                uint8 temp[24];
                memset(temp, 0, len);
                memcpy(temp, wd->i.AsByteArray(), wd->i.GetNumBytes());
                std::reverse(temp, temp + len);
                wd->i.SetBinary((uint8*)temp, len);
            }
        }

        if (type == PLAYER_CHECK || type == MEM_CHECK || type == PAGE_CHECK_A || type == PAGE_CHECK_B || type == PROC_CHECK)
        {
            wd->Address = fields[4].GetUInt32();
            wd->Length = fields[5].GetUInt8();
        }

        // PROC_CHECK support missing
        if (type == PLAYER_CHECK || type == MEM_CHECK || type == MPQ_CHECK || type == LUA_STR_CHECK || type == DRIVE_CHECK)
            wd->str = fields[3].GetCppString();

        if (type == MODULE_CHECK)
        {
            std::string str = fields[3].GetCppString();
            std::transform(str.begin(), str.end(), str.begin(), toupper);

            wd->str = str;
        }

        if (type == MPQ_CHECK || type == MEM_CHECK)
        {
            const std::string result = fields[6].GetCppString();
            const int len = result.size() / 2;

            wd->Result.resize(len);
            uint8 *temp = new uint8[result.size()];
            memcpy(temp, result.c_str(), result.size());

            for (int i = 0; i < len; ++i)
            {
                const char s[3] = { temp[i*2], temp[i*2+1], 0 };

                wd->Result[i] = (uint8)std::strtoul(s, NULL, 16);
            }

            delete[] temp;
        }

        wd->Comment = fields[7].GetCppString();

        m_dataMap[id] = wd;
    } while (result->NextRow());

    delete result;

    sLog.outString();
    sLog.outString(">> Loaded %u warden data and results", count);
}

WardenData *CWardenDataStorage::GetWardenDataById(ScanId id) const
{
    std::map<ScanId, WardenData *>::const_iterator itr = m_dataMap.find(id);

    return itr == m_dataMap.end() ? NULL : itr->second;
}
