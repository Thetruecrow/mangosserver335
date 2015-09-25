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

#include <algorithm>
#include <string>
#include <Auth/WardenKeyGeneration.h>
#include "Common.h"
#include "WorldPacket.h"
#include "WorldSession.h"
#include "Log.h"
#include "Opcodes.h"
#include "ByteBuffer.h"
#include <openssl/md5.h>
#include "World.h"
#include "Player.h"
#include "Util.h"
#include "WardenDataStorage.h"
#include "WardenMac.h"
#include "WardenModuleMac.h"

void WardenMac::Init(WorldSession *client, BigNumber *K)
{
    m_client = client;

    // Generate Warden Key
    SHA1Randx WK(K->AsByteArray(), K->GetNumBytes());
    WK.generate(m_inputKey, 16);
    WK.generate(m_outputKey, 16);

    /*
    Seed: 4D808D2C77D905C41A6380EC08586AFE (0x05 packet)
    Hash: <?> (0x04 packet)
    Module MD5: 0DBBF209A27B1E279A9FEC5C168A15F7
    New Client Key: <?>
    New Cerver Key: <?>
    */

    static const uint8 mod_seed[16] = { 0x4D, 0x80, 0x8D, 0x2C, 0x77, 0xD9, 0x05, 0xC4, 0x1A, 0x63, 0x80, 0xEC, 0x08, 0x58, 0x6A, 0xFE };

    memcpy(m_seed, mod_seed, 16);

    m_iCrypto.Init(m_inputKey);
    m_oCrypto.Init(m_outputKey);

    m_module = GetModuleForClient(m_client);
}

ClientWardenModule *WardenMac::GetModuleForClient(WorldSession *session)
{
    ClientWardenModule *mod = new ClientWardenModule;

    uint32 len = sizeof(Module_0DBBF209A27B1E279A9FEC5C168A15F7_Data);

    // data assign
    mod->CompressedSize = len;
    mod->CompressedData = new uint8[len];
    memcpy(mod->CompressedData, Module_0DBBF209A27B1E279A9FEC5C168A15F7_Data, len);
    memcpy(mod->Key, Module_0DBBF209A27B1E279A9FEC5C168A15F7_Key, 16);
        
    // md5 hash
    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, mod->CompressedData, len);
    MD5_Final((uint8*)&mod->ID, &ctx);

    return mod;
}

void WardenMac::InitializeModule()
{

}

void WardenMac::RequestHash()
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

void WardenMac::HandleHashResult(ByteBuffer &buff)
{
    // test
    int keyIn[4];

    const uint8 mod_seed[16] = { 0x4D, 0x80, 0x8D, 0x2C, 0x77, 0xD9, 0x05, 0xC4, 0x1A, 0x63, 0x80, 0xEC, 0x08, 0x58, 0x6A, 0xFE };

    for(int i = 0; i < 4; ++i)
    {
        keyIn[i] = *(int*)(&mod_seed[0] + i * 4);
    }

    int keyOut[4];
    int keyIn1, keyIn2;
    keyOut[0] = keyIn[0];
    keyIn[0] ^= 0xDEADBEEFu;
    keyIn1 = keyIn[1];
    keyIn[1] -= 0x35014542u;
    keyIn2 = keyIn[2];
    keyIn[2] += 0x5313F22u;
    keyIn[3] *= 0x1337F00Du;
    keyOut[1] = keyIn1 - 0x6A028A84;
    keyOut[2] = keyIn2 + 0xA627E44;
    keyOut[3] = 0x1337F00D * keyIn[3];
    // end test

    buff.rpos(buff.wpos());

    Sha1Hash sha1;
    sha1.UpdateData((uint8*)keyIn, 16);
    sha1.Finalize();

    // verify key not equal kick player
    if (memcmp(buff.contents() + 1, sha1.GetDigest(), 20) != 0)
    {
        m_client->KickPlayer();
        return;
    }

    // change keys here
    memcpy(m_inputKey, keyIn, 16);
    memcpy(m_outputKey, keyOut, 16);

    m_iCrypto.Init(m_inputKey);
    m_oCrypto.Init(m_outputKey);

    m_currentState = Initialized;
    ResetKickTimer(false);
}

void WardenMac::RequestWardenChecks()
{
    ByteBuffer buff;
    buff << uint8(WARDEN_SMSG_CHEAT_CHECKS_REQUEST);

    std::string str = m_client->GetAccountName();
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);

    buff << uint8(str.size());
    buff.append(str.c_str(), str.size());

    // Encrypt with warden RC4 key.
    EncryptData(const_cast<uint8*>(buff.contents()), buff.size());

    WorldPacket pkt(SMSG_WARDEN_DATA, buff.size());
    pkt.append(buff);
    m_client->SendPacket(&pkt);

    ResetKickTimer(true);
}

void WardenMac::HandleData(ByteBuffer &buff)
{
    m_mistakeCounter = 0;
    ResetKickTimer(false);

    bool found = false;

    std::string str = m_client->GetAccountName();
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);

    Sha1Hash sha1;
    sha1.UpdateData(str);
    uint32 magic = 0xFEEDFACE;
    sha1.UpdateData((uint8*)&magic, 4);
    sha1.Finalize();

    uint8 sha1Hash[20];
    buff.read(sha1Hash, 20);

    std::stringstream reason;

    if (memcmp(sha1Hash, sha1.GetDigest(), 20))
    {
        reason << "SHA1 hash failed ";
        found = true;
    }

    MD5_CTX ctx;
    MD5_Init(&ctx);
    MD5_Update(&ctx, str.c_str(), str.size());
    uint8 ourMD5Hash[16];
    MD5_Final(ourMD5Hash, &ctx);

    uint8 theirsMD5Hash[16];
    buff.read(theirsMD5Hash, 16);

    if (memcmp(ourMD5Hash, theirsMD5Hash, 16))
    {
        reason << "MD5 hash is wrong ";
        found = true;
    }

    if (found == false)
        return;

    m_client->KickPlayer();
}