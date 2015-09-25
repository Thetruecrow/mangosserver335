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
#include "Opcodes.h"
#include "ByteBuffer.h"
#include <openssl/md5.h>
#include <openssl/sha.h>
#include "World.h"
#include "Player.h"
#include "Util.h"
#include "WardenBase.h"
#include "WardenWin.h"

WardenBase::WardenBase() : m_iCrypto(16), m_oCrypto(16), m_wardenCheckTimer(10),
    m_kickTimer(0), m_mistakeCounter(0), m_waitingForReply(false), m_currentState(StateNull), m_module(NULL)
{
    RefillNonPlayerScans();
}

WardenBase::~WardenBase()
{
    if (m_module)
    {
        delete[] m_module->CompressedData;
        delete m_module;
    }

    m_module = NULL;

    Uninitialize();
}

void WardenBase::Uninitialize()
{
    if(m_currentState != Initialized)
        return;
    m_mistakeCounter = 0;
    ResetKickTimer(false);
    m_currentState = Uninitialized;
}

void WardenBase::SendModuleToClient()
{
    // Create packet structure
    WardenModuleTransfer pkt;

    uint32 size_left = m_module->CompressedSize, pos = 0;
    uint16 burst_size;
    while (size_left > 0)
    {
        burst_size = size_left < 500 ? size_left : 500;
        pkt.Command = WARDEN_SMSG_MODULE_CACHE;
        pkt.DataSize = burst_size;
        memcpy(pkt.Data, &m_module->CompressedData[pos], burst_size);
        size_left -= burst_size;
        pos += burst_size;

        EncryptData((uint8*)&pkt, burst_size + 3);
        WorldPacket pkt1(SMSG_WARDEN_DATA, burst_size + 3);
        pkt1.append((uint8*)&pkt, burst_size + 3);
        m_client->SendPacket(&pkt1);
    }

    ResetKickTimer(true);
}

void WardenBase::RequestModule()
{
    // Create packet structure
    WardenModuleUse request;

    request.Command = WARDEN_SMSG_MODULE_USE;

    memcpy(request.Module_Id, m_module->ID, 16);
    memcpy(request.Module_Key, m_module->Key, 16);

    request.Size = m_module->CompressedSize;

    // Encrypt with warden RC4 key.
    EncryptData((uint8*)&request, sizeof(WardenModuleUse));

    WorldPacket pkt(SMSG_WARDEN_DATA, sizeof(WardenModuleUse));
    pkt.append((uint8*)&request, sizeof(WardenModuleUse));
    m_client->SendPacket(&pkt);

    ResetKickTimer(true);
}

void WardenBase::Update(uint32 diff)
{
    bool initialized = m_currentState == Initialized;
    if(m_waitingForReply)
    {
        m_kickTimer += diff;
        if (m_kickTimer >= ReplyTimeout)
        {
            m_mistakeCounter++;
            bool kick = (m_mistakeCounter >= 5);
            if(kick == false)
            {
                if(initialized)
                    RequestWardenChecks();
                else if(m_currentState == PlayerLocate)
                    FinishEnteringWorld();
                else kick = true;
            }

            if(kick)
            {
                m_kickTimer = 0; // Prevent server spam
                m_client->KickPlayer();
            }
        }
        return;
    }

    // if we are not initialized, don't send checks
    if (initialized == false)
        return;

    if(m_wardenCheckTimer > diff)
        m_wardenCheckTimer -= diff;
    else
    {
        RequestWardenChecks();
        m_wardenCheckTimer = irand(10, 15) * IN_MILLISECONDS;
    }
}

void WardenBase::OnAuthenticatePass()
{
    RequestModule();
}

void WardenBase::RequestWardenChecks()
{
    std::vector<ScanId> availableScans;
    FillRequests(availableScans);
    if (!availableScans.size())
        return;

    RequestScans(availableScans);
}

void WardenBase::FillRequests(std::vector<ScanId> &results)
{
    // For warden base we can ignore maxChecks
    if (m_nonPlayerScans.size() <= 4)
    {
        // Just fill in our needed scanIds
        results.insert(results.end(), m_nonPlayerScans.begin(), m_nonPlayerScans.end());
        m_nonPlayerScans.clear();
    }
    else
    {
        uint8 count = 0;
        while(count < 4 && !m_nonPlayerScans.empty())
        {
            // Iterate through the vector based on random id
            std::vector<ScanId>::iterator itr = m_nonPlayerScans.begin()+(m_nonPlayerScans.size() == 1 ? 0 : urand(0, m_nonPlayerScans.size()-1));
            if(sWarden.GetWardenDataById(*itr))
            {
                results.push_back(*itr);
                count++;
            }
            // Drop the scanId from our current list
            m_nonPlayerScans.erase(itr);
        }
    }

    // Refill if empty
    if(m_nonPlayerScans.empty())
        RefillNonPlayerScans();
}

void WardenBase::RefillNonPlayerScans()
{
    // Grab the list of vectors from our manager
    std::vector<ScanId> &source = sWarden.GetNonPlayerScans();
    // Fill the vector with new scans
    m_nonPlayerScans.insert(m_nonPlayerScans.end(), source.begin(), source.end());
}

void WardenBase::DecryptData(uint8 *Buffer, uint32 Len)
{
    m_iCrypto.UpdateData(Len, Buffer);
}

void WardenBase::EncryptData(uint8 *Buffer, uint32 Len)
{
    m_oCrypto.UpdateData(Len, Buffer);
}

void WardenBase::DelayScanTimers(uint32 delay)
{
    m_wardenCheckTimer += delay;
}

bool WardenBase::IsValidCheckSum(uint32 checksum, const uint8 *Data, const uint16 Length)
{
    uint32 newchecksum = BuildChecksum(Data, Length);
    if (checksum != newchecksum)
        return false;
    return true;
}

uint32 WardenBase::BuildChecksum(const uint8* data, uint32 dataLen)
{
    uint8 hash[20];
    SHA1(data, dataLen, hash);
    uint32 checkSum = 0;
    for (uint8 i = 0; i < 5; ++i)
        checkSum = checkSum ^ *(uint32*)(&hash[0] + i * 4);
    return checkSum;
}

void WardenBase::HandlePacket(WorldPacket &packet)
{
    DecryptData(const_cast<uint8*>(packet.contents()), packet.size());
    uint8 opCode;
    packet >> opCode;

    try
    {
        switch (opCode)
        {
        case WARDEN_CMSG_MODULE_MISSING:
            SendModuleToClient();
            break;
        case WARDEN_CMSG_MODULE_OK:
            RequestHash();
            break;
        case WARDEN_CMSG_CHEAT_CHECKS_RESULT:
            HandleData(packet);
            break;
        case WARDEN_CMSG_MEM_CHECKS_RESULT:
            sLog.outDebug("NYI WARDEN_CMSG_MEM_CHECKS_RESULT received from %s", m_client->GetPlayerName());
            break;
        case WARDEN_CMSG_HASH_RESULT:
            HandleHashResult(packet);
            InitializeModule();
            break;
        case WARDEN_CMSG_MODULE_FAILED:
            sLog.outDebug("NYI WARDEN_CMSG_MODULE_FAILED received from %s", m_client->GetPlayerName());
            break;
        default:
            sLog.outDebug("WARDEN: Received unknown opcode 0x%02X of size %u from player %s account %u", opCode, packet.size() - 1, m_client->GetPlayerName(), m_client->GetAccountId());
            break;
        }
    }
    catch (ByteBufferException)
    {
        m_client->KickPlayer();
    }
}

void WorldSession::HandleWardenDataOpcode(WorldPacket &recv_data)
{
    if (m_warden != NULL)
        m_warden->HandlePacket(recv_data);
}