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

#ifndef _WARDEN_WIN_H
#define _WARDEN_WIN_H

#include "Auth/SARC4.h"
#include <map>
#include "Auth/BigNumber.h"
#include "ByteBuffer.h"
#include "WardenDataStorage.h"

enum WardenCheckType
{
    PLAYER_CHECK            = 0x00,                         // re-written MEM_CHECK that checks player class memory
    WARDEN_CHECK            = 0x01,                         // re-written MEM_CHECK that checks warden memory
    MEM_CHECK               = 0xF3,                         // byte moduleNameIndex + uint Offset + byte Len (check to ensure memory isn't modified)
    PAGE_CHECK_A            = 0xB2,                         // uint Seed + byte[20] SHA1 + uint Addr + byte Len (scans all pages for specified hash)
    PAGE_CHECK_B            = 0xBF,                         // uint Seed + byte[20] SHA1 + uint Addr + byte Len (scans only pages starts with MZ+PE headers for specified hash)
    MPQ_CHECK               = 0x98,                         // byte fileNameIndex (check to ensure MPQ file isn't modified)
    LUA_STR_CHECK           = 0x8B,                         // byte luaNameIndex (check to ensure LUA string isn't used)
    DRIVE_CHECK             = 0x71,                         // uint Seed + byte[20] SHA1 + byte drive name (checks for existing drive -- NOT DRIVER)
    TIMING_CHECK            = 0x57,                         // empty (check to ensure GetTickCount() isn't detoured)
    PROC_CHECK              = 0x7E,                         // uint Seed + byte[20] SHA1 + byte moduleNameIndex + byte procNameIndex + uint Offset + byte Len (check to ensure proc isn't detoured)
    MODULE_CHECK            = 0xD9,                         // uint Seed + byte[20] SHA1 (check to ensure module isn't injected)
};

#if defined(__GNUC__)
#pragma pack(1)
#else
#pragma pack(push,1)
#endif

// WARNING: If you make this too large the reply packet built by the client can also become too large.
//            In this case, the client will stop replying and innocent users will be kicked.
#define PLAYER_SCAN_COUNT 5

struct WardenInitModuleRequest
{
    uint8 Command1;
    uint16 Size1;
    uint32 CheckSumm1;
    uint8 Unk1;
    uint8 Unk2;
    uint8 Type;
    uint8 String_library1;
    uint32 Function1[4];

    uint8 Command2;
    uint16 Size2;
    uint32 CheckSumm2;
    uint8 Unk3;
    uint8 Unk4;
    uint8 String_library2;
    uint32 Function2;
    uint8 Function2_set;

    uint8 Command3;
    uint16 Size3;
    uint32 CheckSumm3;
    uint8 Unk5;
    uint8 Unk6;
    uint8 String_library3;
    uint32 Function3;
    uint8 Function3_set;
};

struct PlayerMovementData
{
    uint32 curMapId; // Current map id
    float posX, posY, posZ, posO; // Player position at time of mem read
    float vertO; // Vertical orientation
    uint32 padding_0[7]; // Filler
    uint32 movementFlags, movementFlags2; // Movement flags(two bytes since can't do single uint8 store in memory)
    float startX, startY, zWaterOffset, startO, startvertO; // Starting position on map(x, y) | Offset from water top | start orientation, cos orientation angle start
    uint32 padding_1; // Filler
    float forwardAngle[2], turningAngle[3], turnCounter; // Cos and Sin
    uint32 padding_2; // Filler
    uint32 fallTime; // Fall tiem, default 824
    float startZ; // Starting position on map(z)
    uint32 padding_3; // Filler
    float currentSpeed; // Current speed(from below)
    float moveSpeed[MAX_MOVE_TYPE]; // Assigned speeds
    float gravity; // Gravity affecting jump arc
    uint32 padding_4[8];
    float walkStatus; // Default 1
};

#if defined(__GNUC__)
#pragma pack()
#else
#pragma pack(pop)
#endif

class WorldSession;
class WardenBase;

class WardenWin : public WardenBase
{
public:
    WardenWin();

    void Init(WorldSession *pClient, BigNumber *K);

    inline void BeginEnteringWorld() { m_currentState = WaitingForPlayerLocate; }
    inline void BeginCinematic() { m_currentState = WaitingForCinematicComplete; }
    void FinishEnteringWorld();

    inline bool IsWindows() const { return true; }
    inline bool IsWardenConfirmed() const { return m_wardenConfirmed; }

    inline bool PlayerWasDead() const { return m_playerWasDead; }
    inline bool PlayerWasUsingTaxi() const { return m_playerWasUsingTaxi; }
    inline bool PlayerWasRooted() const { return m_playerWasRooted; }
    inline bool PlayerWasSlowFalling() const { return m_playerWasSlowFalling; }
    inline bool PlayerWasWaterWalking() const { return m_playerWasWaterWalking; }
    inline bool PlayerWasLevitating() const { return m_playerWasLevitating; }
    inline bool PlayerWasFlying() const { return m_playerWasFlying; }
    inline float GetHighestSpeed() const { return m_highestSpeed; }
    inline float PlayerSpeed(UnitMoveType i) const { return m_playerSpeeds[i]; }
    inline uint16 GetPlayersTrackingAuras() const { return m_playerTrackingAuras; }
    inline uint16 GetPlayersResourceAuras() const { return m_playerResourceAuras; }

    PlayerMovementData &GetMoveData() { return m_pMoveData; }

private:
    virtual void FillRequests(std::vector<ScanId> &results);
    virtual void RequestScans(const std::vector<ScanId> &requestedIds);

    ClientWardenModule *GetModuleForClient(WorldSession *session);
    void InitializeModule();
    void RequestHash();
    void HandleHashResult(ByteBuffer &buff);
    void HandleData(ByteBuffer &buff);

    void SendWardenLocate();
    void SendPlayerLocate();

    bool m_wardenConfirmed;
    bool m_playerWasDead;
    bool m_playerWasUsingTaxi;
    bool m_playerWasRooted;
    bool m_playerWasSlowFalling;
    bool m_playerWasWaterWalking;
    bool m_playerWasLevitating;
    bool m_playerWasFlying;
    uint16 m_playerTrackingAuras;
    uint16 m_playerResourceAuras;

    float m_highestSpeed;
    float m_playerSpeeds[MAX_MOVE_TYPE];

    PlayerMovementData m_pMoveData;

    uint32 m_serverTicks;           // server ticks at last TIMING_CHECK reply
    uint32 m_clientTicks;           // client ticks at last TIMING_CHECK reply
    uint32 m_playerAddress;
    uint32 m_wardenAddress;

    std::queue<ScanId> m_pendingScanIds;

    static const uint32 WardenLocateAddress = 0xD31A4C;     // from Handler_SMSG_WARDEN_DATA
    static const uint32 PlayerLocateddress  = 0xCD87A8;

    static const uint32 SFileOpenFileOffset         = 0x00024F80;     // 0x00400000 + 0x00024F80 SFileOpenFile
    static const uint32 SFileGetFileSizeOffset      = 0x000218C0;     // 0x00400000 + 0x000218C0 SFileGetFileSize
    static const uint32 SFileReadFileOffset         = 0x00022530;     // 0x00400000 + 0x00022530 SFileReadFile
    static const uint32 SFileCloseFileOffset        = 0x00022910;     // 0x00400000 + 0x00022910 SFileCloseFile
    static const uint32 FrameScriptGetTextOffset    = 0x00419D40;     // 0x00400000 + 0x00419D40 FrameScript::GetText
    static const uint32 PerformanceCounterOffset    = 0x0046AE20;     // 0x00400000 + 0x0046AE20 PerformanceCounter
};

struct PlayerScan
{
    uint16 ScanId;
    bool (*ProcessReply)(ByteBuffer &buff, WorldSession *client, std::stringstream &output);
};

#endif
