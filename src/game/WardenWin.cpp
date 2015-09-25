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

#include <iomanip>
#include <sstream>
#include <string>
#include <list>
#include "Auth/HMACSHA1.h"
#include "Auth/WardenKeyGeneration.h"
#include "Common.h"
#include "WorldPacket.h"
#include "WorldSession.h"
#include "Log.h"
#include "Opcodes.h"
#include "ByteBuffer.h"
#include <openssl/md5.h>
#include "ProgressBar.h"
#include "Database/DatabaseEnv.h"
#include "World.h"
#include "Unit.h"
#include "Player.h"
#include "Util.h"
#include "Timer.h"
#include "WardenWin.h"
#include "WardenModuleWin.h"
#include "WardenDataStorage.h"
#include "SpellAuras.h"
#include "Chat.h"
#include "Language.h"

WardenWin::WardenWin() : WardenBase(), m_wardenConfirmed(false), m_playerWasDead(false), m_playerWasUsingTaxi(false),
m_playerWasRooted(false), m_playerWasSlowFalling(false), m_playerWasWaterWalking(false),
m_playerWasLevitating(false), m_playerWasFlying(false), m_playerTrackingAuras(0), m_playerResourceAuras(0),
m_serverTicks(0), m_clientTicks(0), m_playerBase(0), m_playerOffset(0), m_playerAddress(0)
{

}

void WardenWin::Init(WorldSession *client, BigNumber *K)
{
    m_client = client;

    // Generate Warden Key
    SHA1Randx WK(K->AsByteArray(), K->GetNumBytes());
    WK.generate(m_inputKey, 16);
    WK.generate(m_outputKey, 16);

    memcpy(m_seed, Module.Seed, 16);

    m_iCrypto.Init(m_inputKey);
    m_oCrypto.Init(m_outputKey);

    m_module = GetModuleForClient(m_client);
}

ClientWardenModule *WardenWin::GetModuleForClient(WorldSession *session)
{
    ClientWardenModule *mod = new ClientWardenModule;

    uint32 length = sizeof(Module.Module);

    // data assign
    mod->CompressedSize = length;
    mod->CompressedData = new uint8[length];
    memcpy(mod->CompressedData, Module.Module, length);
    memcpy(mod->Key, Module.ModuleKey, 16);

    // md5 hash
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, mod->CompressedData, length);
    MD5_Final((uint8*)&mod->ID, &ctx);

    return mod;
}

void WardenWin::InitializeModule()
{
    // Create packet structure
    WardenInitModuleRequest Request;
    Request.Command1 = WARDEN_SMSG_MODULE_INITIALIZE;
    Request.Size1 = 20;
    Request.Unk1 = 1;
    Request.Unk2 = 0;
    Request.Type = 1;
    Request.String_library1 = 0;
    Request.Function1[0] = SFileOpenFileOffset;
    Request.Function1[1] = SFileGetFileSizeOffset;
    Request.Function1[2] = SFileReadFileOffset;
    Request.Function1[3] = SFileCloseFileOffset;
    Request.CheckSumm1 = BuildChecksum(&Request.Unk1, Request.Size1);

    Request.Command2 = WARDEN_SMSG_MODULE_INITIALIZE;
    Request.Size2 = 8;
    Request.Unk3 = 4;
    Request.Unk4 = 0;
    Request.String_library2 = 0;
    Request.Function2 = FrameScriptGetTextOffset;
    Request.Function2_set = 1;
    Request.CheckSumm2 = BuildChecksum(&Request.Unk3, Request.Size2);

    Request.Command3 = WARDEN_SMSG_MODULE_INITIALIZE;
    Request.Size3 = 8;
    Request.Unk5 = 1;
    Request.Unk6 = 1;
    Request.String_library3 = 0;
    Request.Function3 = PerformanceCounterOffset;
    Request.Function3_set = 1;
    Request.CheckSumm3 = BuildChecksum(&Request.Unk5, Request.Size3);

    // Encrypt with warden RC4 key.
    EncryptData((uint8*)&Request, sizeof(WardenInitModuleRequest));

    WorldPacket pkt(SMSG_WARDEN_DATA, sizeof(WardenInitModuleRequest));
    pkt.append((uint8*)&Request, sizeof(WardenInitModuleRequest));
    m_client->SendPacket(&pkt);

    SendWardenLocate();
}

void WardenWin::RequestHash()
{
    // Create packet structure
    WardenHashRequest request;

    request.Command = WARDEN_SMSG_HASH_REQUEST;
    memcpy(request.Seed, m_seed, 16);

    // Encrypt with warden RC4 key.
    EncryptData((uint8*)&request, sizeof(WardenHashRequest));

    WorldPacket pkt(SMSG_WARDEN_DATA, sizeof(WardenHashRequest));
    pkt.append((uint8*)&request, sizeof(WardenHashRequest));
    m_client->SendPacket(&pkt);

    ResetKickTimer(true);
}

void WardenWin::HandleHashResult(ByteBuffer &buff)
{
    buff.rpos(buff.wpos());

    // verify key not equal kick player
    if (memcmp(buff.contents() + 1, Module.ClientKeySeedHash, 20) != 0)
    {
        m_client->KickPlayer();
        return;
    }

    // change keys here
    memcpy(m_inputKey, Module.ClientKeySeed, 16);
    memcpy(m_outputKey, Module.ServerKeySeed, 16);

    m_iCrypto.Init(m_inputKey);
    m_oCrypto.Init(m_outputKey);

    ResetKickTimer(false);
}

void WardenWin::SendWardenLocate()
{
    ByteBuffer buff;
    const uint8 xorByte = m_inputKey[0];

    buff << uint8(WARDEN_SMSG_CHEAT_CHECKS_REQUEST);
    buff << uint8(0x00);
    buff << uint8(MEM_CHECK ^ xorByte);
    buff << uint8(0x00);
    buff << uint32(WardenLocateAddress);
    buff << uint8(4);
    buff << uint8(xorByte);

    // Encrypt with warden RC4 key.
    EncryptData(const_cast<uint8*>(buff.contents()), buff.size());

    WorldPacket pkt(SMSG_WARDEN_DATA, buff.size());
    pkt.append(buff);

    m_client->SendPacket(&pkt);

    m_currentState = WardenLocate;

    ResetKickTimer(true);
}

void WardenWin::SendPlayerBaseLocate()
{
    ByteBuffer buff;
    const uint8 xorByte = m_inputKey[0];

    buff << uint8(WARDEN_SMSG_CHEAT_CHECKS_REQUEST);
    buff << uint8(0x00);
    buff << uint8(MEM_CHECK ^ xorByte);
    buff << uint8(0x00);
    buff << uint32(PlayerBaseAddress);
    buff << uint8(4);
    buff << uint8(xorByte);

    // Encrypt with warden RC4 key.
    EncryptData(const_cast<uint8*>(buff.contents()), buff.size());

    WorldPacket pkt(SMSG_WARDEN_DATA, buff.size());
    pkt.append(buff);

    m_client->SendPacket(&pkt);

    m_currentState = PlayerLocateBase;

    ResetKickTimer(true);
}

void WardenWin::SendPlayerOffsetLocate()
{
    ByteBuffer buff;
    const uint8 xorByte = m_inputKey[0];

    buff << uint8(WARDEN_SMSG_CHEAT_CHECKS_REQUEST);
    buff << uint8(0x00);
    buff << uint8(MEM_CHECK ^ xorByte);
    buff << uint8(0x00);
    buff << uint32(m_playerBase+PlayerOffsetAddress);
    buff << uint8(4);
    buff << uint8(xorByte);

    // Encrypt with warden RC4 key.
    EncryptData(const_cast<uint8*>(buff.contents()), buff.size());

    WorldPacket pkt(SMSG_WARDEN_DATA, buff.size());
    pkt.append(buff);

    m_client->SendPacket(&pkt);

    m_currentState = PlayerLocateOffset;

    ResetKickTimer(true);
}

void WardenWin::SendPlayerAddressLocate()
{
    ByteBuffer buff;
    const uint8 xorByte = m_inputKey[0];

    buff << uint8(WARDEN_SMSG_CHEAT_CHECKS_REQUEST);
    buff << uint8(0x00);
    buff << uint8(MEM_CHECK ^ xorByte);
    buff << uint8(0x00);
    buff << uint32(m_playerOffset+PlayerAddressOffset);
    buff << uint8(4);
    buff << uint8(xorByte);

    // Encrypt with warden RC4 key.
    EncryptData(const_cast<uint8*>(buff.contents()), buff.size());

    WorldPacket pkt(SMSG_WARDEN_DATA, buff.size());
    pkt.append(buff);

    m_client->SendPacket(&pkt);

    m_currentState = PlayerLocatePtr;

    ResetKickTimer(true);
}

extern struct PlayerScan PlayerScans[PLAYER_SCAN_COUNT];

void WardenWin::FillRequests(std::vector<ScanId> &results)
{
    Player *player = m_client->GetPlayer();
    if(player == nullptr || !player->IsInWorld())
        return;

    std::vector<ScanId> &source = sWarden.GetPlayerScans();
    // Fill the vector with new scans
    results.insert(results.end(), source.begin(), source.end());
}

bool MovementHackCheck(ByteBuffer &buff, WorldSession *client, std::stringstream &output)
{
    // this shouldn't happen, but if it does, kick the client
    if (!client || !client->GetPlayer())
    {
        buff.read_skip(sizeof(PlayerMovementData));
        return true;
    }

    PlayerMovementData &moveData = ((WardenWin*)client->GetWarden())->GetMoveData();
    buff.read((uint8*)&moveData, sizeof(PlayerMovementData));

    const WardenWin *warden = (const WardenWin *)client->GetWarden();
    Player *player = client->GetPlayer();
    if (player->IsAntiCheatDisabled() || player->IsTaxiFlying() || warden->PlayerWasUsingTaxi())
        return false;

    // Unroot is a bit different, we only check to make sure we have the flag if the status is still in effect or was in effect, never if only one of the two
    if (sWorld.getConfig(CONFIG_BOOL_WARDEN_ROOT_HACK) && warden->PlayerWasRooted() && player->HasAuraType(SPELL_AURA_MOD_ROOT)  && !(moveData.movementFlags & (MOVEFLAG_ROOT|MOVEFLAG_FALLING|MOVEFLAG_FALLINGFAR)))
    {
        output << "Unroot hack. Movement flags: 0x" << std::hex << moveData.movementFlags << std::dec << " Was rooted: true ";
        return true;
    }

    // slow fall
    if (sWorld.getConfig(CONFIG_BOOL_WARDEN_SLOWFALL_HACK) && ((moveData.movementFlags & MOVEFLAG_SAFE_FALL) && !warden->PlayerWasSlowFalling() && !player->HasAuraType(SPELL_AURA_FEATHER_FALL)))
    {
        output << "Slow fall hack. Movement flags: 0x" << std::hex << moveData.movementFlags << " " << std::dec;
        return true;
    }

    // water walk
    if (sWorld.getConfig(CONFIG_BOOL_WARDEN_WATERWALK_HACK) && ((moveData.movementFlags & MOVEFLAG_WATERWALKING) && !warden->PlayerWasDead() && !player->isDead() && !warden->PlayerWasWaterWalking() && !player->HasAuraType(SPELL_AURA_WATER_WALK)))
    {
        output << "Water walk hack. Movement flags: 0x" << std::hex << moveData.movementFlags << " " << std::dec;
        return true;
    }

    // Fly hack checks, can skip levitate checks since levitate is part of flying flags
    if(moveData.movementFlags & (MOVEFLAG_CAN_FLY|MOVEFLAG_FLYING))
    {
        if(sWorld.getConfig(CONFIG_BOOL_WARDEN_FLY_HACK) && !warden->PlayerWasFlying() && !player->CanHaveFlyingMovement())
        {
            output << "Fly hack. Movement flags: 0x" << std::hex << moveData.movementFlags << " " << std::dec;
            return true;
        }
    } // levitate. If the player has the levitate flag, but did not have a levitate aura when the scan was requested
    else if (sWorld.getConfig(CONFIG_BOOL_WARDEN_LEVITATE_HACK) && ((moveData.movementFlags & MOVEFLAG_LEVITATING) && !warden->PlayerWasLevitating() && !player->HasAuraType(SPELL_AURA_HOVER)))
    {
        output << "Levitate hack. Movement flags: 0x" << std::hex << moveData.movementFlags << " " << std::dec;
        return true;
    }

    if(sWorld.getConfig(CONFIG_BOOL_WARDEN_SPEED_HACK))
    {
        float currMaxSpeed = 0.f;
        for(uint8 i = 0; i < MAX_MOVE_TYPE; i++)
            currMaxSpeed = std::max(currMaxSpeed, player->GetSpeed(UnitMoveType(i)));
        currMaxSpeed = std::max(currMaxSpeed, warden->GetHighestSpeed());

        // if they have a value higher than the highest one we have seen yet, they are a hacker
        if (floor(moveData.currentSpeed) > currMaxSpeed)
        {
            output << "Speed hack. Movement speed: " << moveData.currentSpeed << "  Maximum speed: " << currMaxSpeed;
            return true;
        }
    }

    // Air swim hack
    if(sWorld.getConfig(CONFIG_BOOL_WARDEN_AIRSWIM_HACK) && ((moveData.movementFlags & MOVEFLAG_SWIMMING) && !player->GetTerrain()->IsInWater(moveData.posX, moveData.posY, moveData.posZ)))
    {
        output << "Swim hack. Movement flags: " << moveData.movementFlags << "  Position: " << moveData.posX << " " << moveData.posY << " " << moveData.posZ;
        return true;
    }

    return false;
}

bool UnitTrackingCheck(ByteBuffer &buff, WorldSession *client, std::stringstream &output)
{
    const WardenWin *warden = (const WardenWin *)client->GetWarden();
    const Player *player = client->GetPlayer();
    uint16 unitTracking = 0, auraTracking = 0;
    buff >> unitTracking;

    if (client->GetPlayer()->IsAntiCheatDisabled())
        return false;

    // nobody would hack to remove tracking
    if (!unitTracking)
        return false;

    // we also assume someone would not hack to track any one particular creature type for which they know the spell
    if (unitTracking == 0x01 && player->HasSpell(1494))
        return false;
    else if (unitTracking == 0x02 && player->HasSpell(19879))
        return false;
    else if (unitTracking == 0x04 && player->HasSpell(19878))
        return false;
    else if (unitTracking == 0x08 && player->HasSpell(19880))
        return false;
    else if (unitTracking == 0x10 && player->HasSpell(19882))
        return false;
    else if (unitTracking == 0x20 && player->HasSpell(19884))
        return false;
    else if (unitTracking == 0x40 && (player->HasSpell(19883) || player->HasSpell(5225)))
        return false;

    const Unit::AuraList &auras = player->GetAurasByType(SPELL_AURA_TRACK_CREATURES);
    for (Unit::AuraList::const_iterator i = auras.begin(); i != auras.end(); i++)
        auraTracking |= 1 << ((*i)->GetMiscValue() - 1);

    if (unitTracking != auraTracking && unitTracking != warden->GetPlayersTrackingAuras())
    {
        output << "Unit tracking from player: 0x" << std::hex << unitTracking << " actual: 0x" << auraTracking << " " << std::dec;
        return true;
    }
    return false;
}

bool ResourceTrackingCheck(ByteBuffer &buff, WorldSession *client, std::stringstream &output)
{
    const WardenWin *warden = (const WardenWin *)client->GetWarden();
    const Player *player = client->GetPlayer();
    uint16 resourceTracking = 0, auraTracking = 0;
    buff >> resourceTracking;

    if (client->GetPlayer()->IsAntiCheatDisabled())
        return false;

    // nobody would hack to remove tracking
    if (!resourceTracking)
        return false;

    // we also assume someone would not hack to track any one particular resource for which they know the spell
    if (resourceTracking == 0x02 && player->HasSpell(2383))
        return false;
    else if (resourceTracking == 0x04 && player->HasSpell(2580))
        return false;
    else if (resourceTracking == 0x20 && player->HasSpell(2481))
        return false;

    const Unit::AuraList &auras = player->GetAurasByType(SPELL_AURA_TRACK_RESOURCES);
    for (Unit::AuraList::const_iterator i = auras.begin(); i != auras.end(); i++)
        auraTracking |= 1 << ((*i)->GetMiscValue() - 1);

    if (resourceTracking != auraTracking && resourceTracking != warden->GetPlayersResourceAuras())
    {
        output << "Resource tracking from player: 0x" << std::hex << resourceTracking << " actual: 0x" << auraTracking << std::dec;
        return true;
    }
    return false;
}

bool NoClipHackCheck(ByteBuffer &buff, WorldSession *client, std::stringstream &output)
{
    float noClipValue;
    buff >> noClipValue;

    if (client->GetPlayer()->IsAntiCheatDisabled())
        return false;

    if (noClipValue == 0.0f)
    {
        output << "No clip hack.  Player " << client->GetPlayerName() << " Account " << client->GetAccountId();
        return true;
    }

    return false;
}

bool DeathBugCheck(ByteBuffer &buff, WorldSession *client, std::stringstream &output)
{
    uint32 flags;
    buff >> flags;

    if (client->GetPlayer()->IsAntiCheatDisabled())
        return false;

    if (flags == 0x270F && client->GetPlayer()->isDead())
    {
        output << "Death bug hack ";
        return true;
    }

    return false;
}

struct PlayerScan PlayerScans[PLAYER_SCAN_COUNT] = {
    { 0, MovementHackCheck },       // slow fall, water walk, levitate, fly hack, movement speed
    { 1, UnitTrackingCheck },       // beasts, dragonkin, humanoids, etc.
    { 2, ResourceTrackingCheck },   // veins, herbs, treasure
    { 3, NoClipHackCheck },         // no-clip, walk through walls, floor, doors, etc
    { 4, DeathBugCheck },           // death bug
};

void WardenWin::RequestScans(const std::vector<ScanId> &requestedIds)
{
    ByteBuffer buff;
    buff << uint8(WARDEN_SMSG_CHEAT_CHECKS_REQUEST);

    std::queue<ScanId> enqueuedScanIds;

    for (uint32 i = 0; i < requestedIds.size(); ++i)                             // for now include 5 random checks
    {
        const ScanId scanId = requestedIds[i];
        const WardenData *wd = sWarden.GetWardenDataById(scanId);

        if (!wd)
            continue;

        enqueuedScanIds.push(scanId);
        switch (wd->Type)
        {
            case MPQ_CHECK:
            case LUA_STR_CHECK:
            case DRIVE_CHECK:
                buff << uint8(wd->str.size());
                buff.append(wd->str.c_str(), wd->str.size());
                break;
            default:
                break;
        }
    }

    const uint8 xorByte = m_inputKey[0];

    buff << uint8(0x00);
    buff << uint8(TIMING_CHECK ^ xorByte);                  // check TIMING_CHECK

    if(!m_pendingScanIds.empty())
        std::swap(m_pendingScanIds, std::queue<ScanId>());

    uint8 index = 1;
    while (!enqueuedScanIds.empty())
    {
        const ScanId scanId = enqueuedScanIds.front();
        enqueuedScanIds.pop();

        m_pendingScanIds.push(scanId);

        WardenData *wd = sWarden.GetWardenDataById(scanId);
        const uint8 type = wd->Type;
        const uint8 typeToSend = type == PLAYER_CHECK ? MEM_CHECK : type;

        buff << uint8(typeToSend ^ xorByte);

        switch (type)
        {
            case PLAYER_CHECK:
            case WARDEN_CHECK:
            case MEM_CHECK:
            {
                uint32 address = 0;
                if (type == PLAYER_CHECK)
                    address = m_playerAddress;
                else if (type == WARDEN_CHECK)
                    address = m_wardenAddress;

                address += wd->Address;

                buff << uint8(0x00);
                buff << uint32(address);
                buff << uint8(wd->Length);
                break;
            }
            case PAGE_CHECK_A:
            case PAGE_CHECK_B:
            {
                const uint32 seed = static_cast<uint32>(rand32());
                buff << uint32(seed);

                HMACSHA1 hmac(4, (uint8*)&seed);
                hmac.UpdateData(wd->i.AsByteArray(0, false), wd->i.GetNumBytes());
                hmac.Finalize();

                buff.append(hmac.GetDigest(), hmac.GetLength());

                break;
            }
            case MPQ_CHECK:
            case LUA_STR_CHECK:
            {
                buff << uint8(index++);
                break;
            }
/*
        private void DoDriverCheck(byte id)
        {
            Logger.InfoFormat("DRIVE_CHECK");
            var packet2 = new Packet();
            packet2.PutByte(2); // opcode
            var dev = "C:";
            packet2.PutString(dev); // device name
            packet2.PutByte(0); // string terminator
            packet2.PutByte((byte)(id ^ xor)); // check
            byte[] seed3, hash3;
            HashDevice(dev, out seed3, out hash3);
            packet2.PutBytes(seed3); // seed
            packet2.PutBytes(hash3); // hash
            packet2.PutByte(1); // string index
            packet2.PutByte(xor); // xor byte

            //lastsize = packet2.Data.Length;
            m_loader.PacketHandler(packet2.Data);
        }

        public static bool HashDevice(string name, out byte[] seed, out byte[] hash)
        {
            var sb = new StringBuilder();

            var res = Native.QueryDosDeviceA(name, sb, Native.MAX_PATH);

            if (res > 0)
            {
                var dev = sb.ToString();
                HashBytes(Encoding.ASCII.GetBytes(dev), out seed, out hash);
                return true;
            }
            else
            {
                seed = null;
                hash = null;
                return false;
            }
        }

        public static void HashBytes(byte[] bytes, out byte[] seed, out byte[] hash)
        {
            Logger.InfoFormat("Hashing bytes: {0}", bytes.ToHexString());
            Random rnd = new Random();
            var buf = new byte[4];
            rnd.NextBytes(buf);
            seed = buf;
            HMACSHA1 hmac = new HMACSHA1(buf);
            hash = hmac.ComputeHash(bytes);
        }
*/
            case DRIVE_CHECK:
            {
                buff.append(wd->i.AsByteArray(0, false), wd->i.GetNumBytes());
                buff << uint8(index++);
                break;
            }
            case MODULE_CHECK:
            {
                uint32 seed = static_cast<uint32>(rand32());
                buff << uint32(seed);

                HMACSHA1 hmac(4, (uint8*)&seed);
                hmac.UpdateData(wd->str);
                hmac.Finalize();

                buff.append(hmac.GetDigest(), hmac.GetLength());
                break;
            }
            /*case PROC_CHECK:
            {
                buff.append(wd->i.
                AsByteArray(0, false), wd->i.GetNumBytes());
                buff << uint8(index++);
                buff << uint8(index++);
                buff << uint32(wd->Address);
                buff << uint8(wd->Length);
                break;
            }*/
            default:
                break;                                      // should never happens
        }
    }

    buff << uint8(xorByte);

    // Encrypt with warden RC4 key.
    EncryptData(const_cast<uint8*>(buff.contents()), buff.size());

    WorldPacket pkt(SMSG_WARDEN_DATA, buff.size());
    pkt.append(buff);

    m_client->SendPacket(&pkt);

    const Player *pl = m_client->GetPlayer();
    // save basic player state for hack checking when the client replies
    m_playerWasDead = !pl->isAlive();
    m_playerWasUsingTaxi = pl->IsTaxiFlying();
    m_playerWasRooted = pl->HasAuraType(SPELL_AURA_MOD_ROOT);
    m_playerWasSlowFalling = pl->HasAuraType(SPELL_AURA_FEATHER_FALL);
    m_playerWasWaterWalking = pl->HasAura(SPELL_AURA_WATER_WALK);
    if(m_playerWasFlying = pl->CanHaveFlyingMovement())
        m_playerWasLevitating = true;
    else m_playerWasLevitating = pl->HasAura(SPELL_AURA_HOVER);

    m_highestSpeed = 0.f;
    for (uint8 i = 0; i < MAX_MOVE_TYPE; ++i)
    {
        m_playerSpeeds[i] = m_client->GetPlayer()->GetSpeed(UnitMoveType(i));
        if(m_playerSpeeds[i] > m_highestSpeed) m_highestSpeed = m_playerSpeeds[i];
    }

    m_playerTrackingAuras = 0;
    const Unit::AuraList &creatureAuras = m_client->GetPlayer()->GetAurasByType(SPELL_AURA_TRACK_CREATURES);
    for (Unit::AuraList::const_iterator i = creatureAuras.begin(); i != creatureAuras.end(); i++)
        m_playerTrackingAuras |= 1 << ((*i)->GetMiscValue() - 1);

    m_playerResourceAuras = 0;
    const Unit::AuraList &resourceAuras = m_client->GetPlayer()->GetAurasByType(SPELL_AURA_TRACK_RESOURCES);
    for (Unit::AuraList::const_iterator i = resourceAuras.begin(); i != resourceAuras.end(); i++)
        m_playerResourceAuras |= 1 << ((*i)->GetMiscValue() - 1);

    ResetKickTimer(true);
}

void WardenWin::HandleData(ByteBuffer &buff)
{
    m_mistakeCounter = 0;
    ResetKickTimer(false);

    // if we are still waiting for the player to enter the world, it is possible to receive
    // a reply to a request which was sent before the player left the world (in the case of
    // switching continents), which can produce invalid data.  ignore the response entirely
    // in this case.  do the same if the player has logged out
    if (m_pendingScanIds.size() && m_currentState == WaitingForPlayerLocate)
    {
        buff.rpos(buff.wpos());

        // efficiently empty the queue
        std::swap(m_pendingScanIds, std::queue<ScanId>());
        return;
    }

    bool kick = false;
    std::stringstream reason;

    uint16 length;
    buff >> length;
    if(length == 0) // Warden will never send empty data
    {
        buff.rpos(buff.wpos());
        kick = true;

        // efficiently empty the queue
        std::swap(m_pendingScanIds, std::queue<ScanId>());
    }
    else
    {
        uint32 dataChecksum;
        buff >> dataChecksum;

        // Prep the target buffer for the chunk data
        ByteBuffer warden_packet(length);
        warden_packet.resize(length);
        // Read out our warden data into our new buffer
        buff.read((uint8*)warden_packet.contents(), length);
        // Check the validity of the warden contents
        if (!IsValidCheckSum(dataChecksum, warden_packet.contents(), length))
        {
            m_client->KickPlayer();
            return;
        }

        std::stringstream debugLog;
        // Remove any remaining data we don't need
        if(buff.rpos() != buff.size())
        {
            sLog.outDebug("Warden packet has unprocessed data at tail");
            buff.rpos(buff.size());
        }

        if(m_currentState == WardenLocate)
        {
            if (uint8 memResult = warden_packet.read<uint8>())
            {
                m_client->KickPlayer();
                return;
            }

            if ((m_wardenAddress = warden_packet.read<uint32>()) == 0)
            {
                m_client->KickPlayer();
                return;
            }

            m_wardenConfirmed = true;
            m_currentState = Uninitialized;
            if(m_client->CharEnumReceived())
                m_client->HandleCharEnumOpcode(WorldPacket());
            return;
        }
        else if (m_currentState == PlayerLocateBase)
        {
            if (uint8 memResult = warden_packet.read<uint8>())
            {
                m_client->KickPlayer();
                return;
            }

            if ((m_playerBase = warden_packet.read<uint32>()) == 0)
            {
                m_client->KickPlayer();
                return;
            }

            SendPlayerOffsetLocate();
            return;
        }
        else if (m_currentState == PlayerLocateOffset)
        {
            if (uint8 memResult = warden_packet.read<uint8>())
            {
                m_client->KickPlayer();
                return;
            }

            if ((m_playerOffset = warden_packet.read<uint32>()) == 0)
            {
                m_client->KickPlayer();
                return;
            }

            SendPlayerAddressLocate();
            return;
        }
        else if (m_currentState == PlayerLocatePtr)
        {
            if (uint8 memResult = warden_packet.read<uint8>())
            {
                m_client->KickPlayer();
                return;
            }

            if ((m_playerAddress = warden_packet.read<uint32>()) == 0)
            {
                m_client->KickPlayer();
                return;
            }

            m_currentState = Initialized;
            return;
        }
        else
        {
            //TIMING_CHECK
            {
                const uint32 ticksNow = WorldTimer::getMSTime();

                uint8 result;
                uint32 newClientTicks;
                warden_packet >> result >> newClientTicks;

                if (!result)
                {
                    reason << "TIMING_CHECK failed ";
                    //kick = true;
                }

                m_serverTicks = ticksNow;
                m_clientTicks = newClientTicks;
            }

            while (!m_pendingScanIds.empty())
            {
                if(kick == true)
                {   // End the queue process here, and empty pending scans
                    // efficiently empty the queue
                    std::swap(m_pendingScanIds, std::queue<ScanId>());
                    break;
                }

                const ScanId scanId = m_pendingScanIds.front();
                m_pendingScanIds.pop();
                debugLog << " " << scanId;

                WardenData *rd = sWarden.GetWardenDataById(scanId);
                const uint8 type = rd->Type;
                switch (type)
                {
                case PLAYER_CHECK:
                    {
                        if (uint8 memResult = warden_packet.read<uint8>())
                        {
                            reason << "MEM_CHECK failed (PLAYER_CHECK) " << rd->Comment << " ";
                            kick = true;
                            continue;
                        }

                        for (uint8 i = 0; i < PLAYER_SCAN_COUNT; i++)
                        {
                            if (PlayerScans[i].ScanId != scanId)
                                continue;

                            if (PlayerScans[i].ProcessReply(warden_packet, m_client, reason))
                                kick = true;

                            break;
                        }
                    }break;
                case MEM_CHECK:
                    {
                        if (uint8 memResult = warden_packet.read<uint8>())
                        {
                            kick = true;
                            reason << "MEM_CHECK failed " << rd->Comment << " ";
                            continue;
                        }

                        uint8 *buffer = new uint8[rd->Length];
                        // Todo: Put in try catch to debug unexpected lengths
                        warden_packet.read(buffer, rd->Length);
                        const uint8 *contents = &rd->Result[0];
                        if(memcmp(buffer, contents, rd->Length) != 0)
                        {
                            reason << "MEM_CHECK " << rd->Comment << " Expected:";

                            const uint8 rpos = warden_packet.rpos();

                            for (uint8 i = 0; i < rd->Length; ++i)
                                reason << " 0x" << std::hex << std::uppercase << (uint32)contents[i] << std::dec << std::nouppercase;

                            reason << " Received:";

                            for (uint8 i = 0; i < rd->Length; ++i)
                                reason << " 0x" << std::hex << std::uppercase << (uint32)buffer[i] << std::dec << std::nouppercase;

                            reason << " ";
                            delete [] buffer;
                            kick = true;
                            continue;
                        }

                        delete [] buffer;
                    }break;
                case PAGE_CHECK_A:
                case PAGE_CHECK_B:
                case DRIVE_CHECK:
                case MODULE_CHECK:
                    {
                        uint8 expected = 0;
                        const uint8 byte = 0xE9;
                        if((expected = warden_packet.read<uint8>()) != byte)
                        {
                            if (type == PAGE_CHECK_A || type == PAGE_CHECK_B)
                                reason << "PAGE_CHECK failed " << rd->Comment << " ";
                            else if (type == MODULE_CHECK)
                                reason << "MODULE_CHECK failed " << rd->Comment << " ";
                            else if (type == DRIVE_CHECK)
                                reason << "DRIVE_CHECK failed " << rd->Comment << " ";
                            kick = true;
                            continue;
                        }               
                    }break;
                case LUA_STR_CHECK:
                    {
                        if (uint8 luaResult = warden_packet.read<uint8>())
                        {
                            reason << "LUA_STR_CHECK failed " << rd->Comment << " ";
                            kick = true;
                            continue;
                        }

                        if(uint8 luaStrLen = warden_packet.read<uint8>())
                        {
                            char *luaStr = new char[luaStrLen+1];
                            // Null out the lua string
                            memset(luaStr, 0, luaStrLen + 1);
                            // Read string without null terminator from client
                            warden_packet.read((uint8*)luaStr, luaStrLen);
                            delete []luaStr;
                        }
                    }break;
                case MPQ_CHECK:
                    {
                        if (uint8 mpqResult = warden_packet.read<uint8>())
                        {
                            reason << "MPQ_CHECK failed " << rd->Comment << " ";
                            kick = true;
                            continue;
                        }

                        uint8 *buffer = new uint8[20]; // Todo: Put in try catch to debug unexpected lengths
                        warden_packet.read(buffer, 20);
                        const uint8 *contents = &rd->Result[0];
                        if(memcmp(buffer, contents, 20) != 0)
                        {
                            reason << "MPQ_CHECK " << rd->Comment << " ";
                            delete [] buffer;
                            kick = true;
                            continue;
                        }

                        delete [] buffer;
                    }break;
                default: break; // Shouldn't happen
                }
            }

            if(kick == false && warden_packet.rpos() != warden_packet.size())
                sLog.outDebug("Warden data packet contains unprocessed data! %u out of %u processed", warden_packet.rpos(), warden_packet.size());
        }
    }

    if (kick == true)
        m_client->KickPlayer();
}

void WardenWin::FinishEnteringWorld()
{
    if(m_currentState == PlayerLocatePtr)
        SendPlayerAddressLocate();
    else if(m_currentState == PlayerLocateOffset)
        SendPlayerOffsetLocate();
    else SendPlayerBaseLocate();
}
