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

#ifndef _WARDEN_BASE_H
#define _WARDEN_BASE_H

#include "Auth/SARC4.h"
#include <map>
#include "Auth/BigNumber.h"
#include "ByteBuffer.h"
#include "WardenDataStorage.h"

enum WardenOpcodes
{
    // Client->Server
    WARDEN_CMSG_MODULE_MISSING                  = 0,
    WARDEN_CMSG_MODULE_OK                       = 1,
    WARDEN_CMSG_CHEAT_CHECKS_RESULT             = 2,
    WARDEN_CMSG_MEM_CHECKS_RESULT               = 3,        // only sent if MEM_CHECK bytes doesn't match
    WARDEN_CMSG_HASH_RESULT                     = 4,
    WARDEN_CMSG_MODULE_FAILED                   = 5,        // this is sent when client failed to load uploaded module due to cache fail

    // Server->Client
    WARDEN_SMSG_MODULE_USE                      = 0,
    WARDEN_SMSG_MODULE_CACHE                    = 1,
    WARDEN_SMSG_CHEAT_CHECKS_REQUEST            = 2,
    WARDEN_SMSG_MODULE_INITIALIZE               = 3,
    WARDEN_SMSG_MEM_CHECKS_REQUEST              = 4,        // byte len; whole(!EOF) { byte unk(1); byte index(++); string module(can be 0); int offset; byte len; byte[] bytes_to_compare[len]; }
    WARDEN_SMSG_HASH_REQUEST                    = 5
};

#if defined(__GNUC__)
#pragma pack(1)
#else
#pragma pack(push,1)
#endif

struct WardenModuleUse
{
    uint8 Command;
    uint8 Module_Id[16];
    uint8 Module_Key[16];
    uint32 Size;
};

struct WardenModuleTransfer
{
    uint8 Command;
    uint16 DataSize;
    uint8 Data[500];
};

struct WardenHashRequest
{
    uint8 Command;
    uint8 Seed[16];
};

#if defined(__GNUC__)
#pragma pack()
#else
#pragma pack(pop)
#endif

struct ClientWardenModule
{
    uint8 ID[16];
    uint8 Key[16];
    uint32 CompressedSize;
    uint8 *CompressedData;
};

class WorldSession;

enum WardenState
{
    StateNull,
    WardenLocate,
    Uninitialized,
    WaitingForCinematicComplete,
    WaitingForPlayerLocate,
    PlayerLocateBase,
    PlayerLocateOffset,
    PlayerLocatePtr,
    Initialized,
};

class WardenBase
{
    public:
        WardenBase();
        ~WardenBase();

        void Uninitialize();

        void HandlePacket(WorldPacket &);
        void Update(uint32 diff);
        void OnAuthenticatePass();
        void ResetKickTimer(bool waiting)
        {
            m_kickTimer = 0;
            m_waitingForReply = waiting;
        }

        virtual void Init(WorldSession *session, BigNumber *K) = 0;
        virtual void BeginEnteringWorld() = 0;
        virtual void FinishEnteringWorld() = 0;
        virtual bool IsWindows() const = 0;

        virtual void DelayScanTimers(uint32 delay);

        inline WardenState GetCurrentState() const { return m_currentState; }

    protected:
        static uint32 BuildChecksum(const uint8 *data, uint32 dataLen);
        static bool IsValidCheckSum(uint32 checksum, const uint8 *data, const uint16 length);

        void RequestModule();
        virtual void RequestWardenChecks();
        virtual void FillRequests(std::vector<ScanId> &results);
        virtual void RequestScans(const std::vector<ScanId> &requestedIds) { };

        virtual ClientWardenModule *GetModuleForClient(WorldSession *session) = 0;
        virtual void InitializeModule() = 0;
        virtual void RequestHash() = 0;
        virtual void HandleHashResult(ByteBuffer &buff) = 0;
        virtual void HandleData(ByteBuffer &buff) = 0;

        void EncryptData(uint8 *buffer, uint32 len);

        WardenState m_currentState;

        WorldSession *m_client;

        uint8 m_inputKey[16];
        uint8 m_outputKey[16];
        uint8 m_seed[16];

        SARC4 m_iCrypto;
        SARC4 m_oCrypto;

        bool m_waitingForReply;

        uint32 m_mistakeCounter;
        uint32 m_kickTimer;          // time after send packet

        ClientWardenModule *m_module;

#define BANNING_NAME "Anti Cheat"
#define BANNING_REASON "Detected hack"

        static const uint32 EnterWorldDelay = 30 * IN_MILLISECONDS;

    private:
        void SendModuleToClient();
        void DecryptData(uint8 *buffer, uint32 len);

        uint32 m_wardenCheckTimer;

        void RefillNonPlayerScans();
        std::vector<ScanId> m_nonPlayerScans;

        static const uint32 ReplyTimeout = 20 * IN_MILLISECONDS;
};

#endif
