/**
 * This code is part of MaNGOS. Contributor & Copyright details are in AUTHORS/THANKS.
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
#include "UpdateData.h"
#include "ByteBuffer.h"
#include "WorldPacket.h"
#include "Log.h"
#include "Opcodes.h"
#include "World.h"
#include "ObjectGuid.h"
#include <zlib/zlib.h>

INSTANTIATE_SINGLETON_1( UpdateDataHeapManager );

UpdateDataHeapManager::UpdateDataHeapManager()
{
    m_allocatedHeaps.clear();
}

uint8 *UpdateDataHeapManager::GetorAllocateHeap(uint32 size)
{
    uint8 *buff = NULL;
    AllocationMap::iterator itr = m_allocatedHeaps.find(GetCurrentThreadId());
    if(itr == m_allocatedHeaps.end())
    {   // We need to construct a new buffer and push it to our thread's pool
        m_allocatedHeaps[GetCurrentThreadId()] = new AllocationBlock();
        itr = m_allocatedHeaps.find(GetCurrentThreadId());
    }

    uint8 i = itr->second->bufferStateMap.size();
    for(std::unordered_map<uint8, uint8 >::iterator iter = itr->second->bufferStateMap.begin(); iter != itr->second->bufferStateMap.end(); iter++)
    {
        if(iter->second == 0)
        {
            i = iter->first;
            break;
        }
    }

    bool createNew = true;
    if(itr->second->bufferMap.find(i) != itr->second->bufferMap.end())
    {
        if(itr->second->bufferSizeMap.at(i) >= size)
            createNew = false;
        else
            delete [] itr->second->bufferMap[i];
    }

    if(createNew)
    {
        itr->second->bufferSizeMap[i] = size;
        itr->second->bufferMap[i] = new uint8[size];
    }
    itr->second->bufferStateMap[i] = 1;
    buff = itr->second->bufferMap.at(i);
    return buff;
}

void UpdateDataHeapManager::CleanHeap(void *ptr)
{
    bool found = false;
    AllocationMap::iterator itr = m_allocatedHeaps.find(GetCurrentThreadId());
    if(itr != m_allocatedHeaps.end())
    {
        AllocationBlock *block = m_allocatedHeaps[GetCurrentThreadId()];
        for(std::unordered_map<uint8, uint8* >::iterator iter = block->bufferMap.begin(); iter != block->bufferMap.end(); iter++)
        {
            if(iter->second == ptr)
            {
                found = true;
                block->bufferStateMap[iter->first] = 0;
                break;
            }
        }
    }
    if(found == false)
        delete [] ptr;
}

void UpdateDataHeapManager::CleanAllHeaps()
{
    for(AllocationMap::iterator itr1 = m_allocatedHeaps.begin(); itr1 != m_allocatedHeaps.end(); itr1++)
    {
        AllocationBlock *block = itr1->second;
        block->bufferSizeMap.clear();
        block->bufferStateMap.clear();
        for(std::unordered_map<uint8, uint8* >::iterator blockItr = block->bufferMap.begin(); blockItr != block->bufferMap.end(); blockItr++)
            delete [] blockItr->second;
        block->bufferMap.clear();
        delete block;
    }
    m_allocatedHeaps.clear();
}

inline void* customAllocate(void *opaque, unsigned int items, unsigned int size)
{
    return (void*)sUpdateDataHeapMgr.GetorAllocateHeap(items * size);
}

inline void customFree(void *opaque, void *ptr)
{
    sUpdateDataHeapMgr.CleanHeap(ptr);
}

UpdateData::UpdateData() : m_outofRangeCount(0)
{
}

void UpdateData::AddOutOfRangeGUID(GuidSet& guids)
{
    for(GuidSet::iterator itr = guids.begin(); itr != guids.end(); itr++)
        AddOutOfRangeGUID(*itr);
}

void UpdateData::AddOutOfRangeGUID(ObjectGuid const& guid)
{
    m_outofRange << guid.WriteAsPacked();
    m_outofRangeCount++;
    if(guid.IsPlayer())
        outofRangePlayers.insert(guid.GetCounter());
}

void UpdateData::AddUpdateBlock(const ByteBuffer& block)
{
    if(m_bufferSet.empty()) // Push new buff to the rear
        m_bufferSet.push_back(new BufferStacks());
    // Acquire our buffer stack
    BufferStacks *stack = m_bufferSet.back();
    if(stack->buff.size() + block.size() >= 65000)
        m_bufferSet.push_back(stack = new BufferStacks());
    // Append block to buffer stack
    stack->buff.append(block);
    stack->count++;
}

void UpdateData::Compress(void* dst, uint32* dst_size, void* src, int src_size)
{
    z_stream c_stream;

    c_stream.zalloc = (alloc_func)customAllocate;
    c_stream.zfree = (free_func)customFree;
    c_stream.opaque = (voidpf)0;

    // default Z_BEST_SPEED (1)
    int z_res = deflateInit(&c_stream, sWorld.getConfig(CONFIG_UINT32_COMPRESSION));
    if (z_res != Z_OK)
    {
        sLog.outError("Can't compress update packet (zlib: deflateInit) Error code: %i (%s)", z_res, zError(z_res));
        *dst_size = 0;
        return;
    }

    c_stream.next_out = (Bytef*)dst;
    c_stream.avail_out = *dst_size;
    c_stream.next_in = (Bytef*)src;
    c_stream.avail_in = (uInt)src_size;

    z_res = deflate(&c_stream, Z_NO_FLUSH);
    if (z_res != Z_OK)
    {
        sLog.outError("Can't compress update packet (zlib: deflate) Error code: %i (%s)", z_res, zError(z_res));
        *dst_size = 0;
        return;
    }

    if (c_stream.avail_in != 0)
    {
        sLog.outError("Can't compress update packet (zlib: deflate not greedy)");
        *dst_size = 0;
        return;
    }

    z_res = deflate(&c_stream, Z_FINISH);
    if (z_res != Z_STREAM_END)
    {
        sLog.outError("Can't compress update packet (zlib: deflate should report Z_STREAM_END instead %i (%s)", z_res, zError(z_res));
        *dst_size = 0;
        return;
    }

    z_res = deflateEnd(&c_stream);
    if (z_res != Z_OK)
    {
        sLog.outError("Can't compress update packet (zlib: deflateEnd) Error code: %i (%s)", z_res, zError(z_res));
        *dst_size = 0;
        return;
    }

    *dst_size = c_stream.total_out;
}

bool UpdateData::BuildPacket(WorldPacket* packet)
{
    MANGOS_ASSERT(packet->empty());                         // shouldn't happen

    BufferStacks *stack = NULL;
    if(!m_bufferSet.empty())
    {
        stack = m_bufferSet.front();
        m_bufferSet.pop_front();
    }

    if(uint32 count = (stack ? stack->count : 0) + (m_outofRangeCount ? 1 : 0))
    {
        ByteBuffer buf(4 + 1 + (m_outofRangeCount ? 1 + 4 + m_outofRange.size() : 0) + (stack ? stack->buff.size() : 0));
        buf << uint32(count);

        if(m_outofRangeCount)
        {
            buf << uint8(UPDATETYPE_OUT_OF_RANGE_OBJECTS);
            buf << uint32(m_outofRangeCount);
            buf.append(m_outofRange);
            m_outofRangeCount = 0;
            m_outofRange.clear();
        }

        if(stack)
        {
            buf.append(stack->buff);
            delete stack;
        }

        size_t pSize = buf.wpos();                              // use real used data size
        if (pSize > 100 )                                       // compress large packets
        {
            uint32 destsize = compressBound(pSize);
            packet->resize( destsize + sizeof(uint32) );

            packet->put<uint32>(0, pSize);
            Compress(const_cast<uint8*>(packet->contents()) + sizeof(uint32), &destsize, (void*)buf.contents(), pSize);
            if (destsize == 0)
                return -1;

            packet->resize( destsize + sizeof(uint32) );
            packet->SetOpcode( SMSG_COMPRESSED_UPDATE_OBJECT );
        }
        else                                                    // send small packets without compression
        {
            packet->append( buf );
            packet->SetOpcode( SMSG_UPDATE_OBJECT );
        }
    }

    return m_bufferSet.size();
}

void UpdateData::Clear()
{
    while(!m_bufferSet.empty())
    {
        BufferStacks *stack = m_bufferSet.front();
        m_bufferSet.pop_front();
        delete stack;
    }

    m_outofRangeCount = 0;
    m_outofRange.clear();
    outofRangePlayers.clear();
}
