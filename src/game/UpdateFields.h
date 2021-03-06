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

#ifndef _UPDATEFIELDS_AUTO_H
#define _UPDATEFIELDS_AUTO_H

// Auto generated for version 3, 3, 5, 12340

enum EObjectFields
{
    OBJECT_FIELD_GUID                         = 0x0000, // Size: 2, Type: LONG, Flags: PUBLIC
    OBJECT_FIELD_TYPE                         = 0x0002, // Size: 1, Type: INT, Flags: PUBLIC
    OBJECT_FIELD_ENTRY                        = 0x0003, // Size: 1, Type: INT, Flags: PUBLIC
    OBJECT_FIELD_SCALE_X                      = 0x0004, // Size: 1, Type: FLOAT, Flags: PUBLIC
    OBJECT_FIELD_PADDING                      = 0x0005, // Size: 1, Type: INT, Flags: NONE
    OBJECT_END                                = 0x0006,
};

enum EItemFields
{
    ITEM_FIELD_OWNER                          = OBJECT_END + 0x0000, // Size: 2, Type: LONG, Flags: PUBLIC
    ITEM_FIELD_CONTAINED                      = OBJECT_END + 0x0002, // Size: 2, Type: LONG, Flags: PUBLIC
    ITEM_FIELD_CREATOR                        = OBJECT_END + 0x0004, // Size: 2, Type: LONG, Flags: PUBLIC
    ITEM_FIELD_GIFTCREATOR                    = OBJECT_END + 0x0006, // Size: 2, Type: LONG, Flags: PUBLIC
    ITEM_FIELD_STACK_COUNT                    = OBJECT_END + 0x0008, // Size: 1, Type: INT, Flags: OWNER, ITEM_OWNER
    ITEM_FIELD_DURATION                       = OBJECT_END + 0x0009, // Size: 1, Type: INT, Flags: OWNER, ITEM_OWNER
    ITEM_FIELD_SPELL_CHARGES                  = OBJECT_END + 0x000A, // Size: 5, Type: INT, Flags: OWNER, ITEM_OWNER
    ITEM_FIELD_FLAGS                          = OBJECT_END + 0x000F, // Size: 1, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_1_1                = OBJECT_END + 0x0010, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_1_3                = OBJECT_END + 0x0012, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_2_1                = OBJECT_END + 0x0013, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_2_3                = OBJECT_END + 0x0015, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_3_1                = OBJECT_END + 0x0016, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_3_3                = OBJECT_END + 0x0018, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_4_1                = OBJECT_END + 0x0019, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_4_3                = OBJECT_END + 0x001B, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_5_1                = OBJECT_END + 0x001C, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_5_3                = OBJECT_END + 0x001E, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_6_1                = OBJECT_END + 0x001F, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_6_3                = OBJECT_END + 0x0021, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_7_1                = OBJECT_END + 0x0022, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_7_3                = OBJECT_END + 0x0024, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_8_1                = OBJECT_END + 0x0025, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_8_3                = OBJECT_END + 0x0027, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_9_1                = OBJECT_END + 0x0028, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_9_3                = OBJECT_END + 0x002A, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_10_1               = OBJECT_END + 0x002B, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_10_3               = OBJECT_END + 0x002D, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_11_1               = OBJECT_END + 0x002E, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_11_3               = OBJECT_END + 0x0030, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_12_1               = OBJECT_END + 0x0031, // Size: 2, Type: INT, Flags: PUBLIC
    ITEM_FIELD_ENCHANTMENT_12_3               = OBJECT_END + 0x0033, // Size: 1, Type: TWO_SHORT, Flags: PUBLIC
    ITEM_FIELD_PROPERTY_SEED                  = OBJECT_END + 0x0034, // Size: 1, Type: INT, Flags: PUBLIC
    ITEM_FIELD_RANDOM_PROPERTIES_ID           = OBJECT_END + 0x0035, // Size: 1, Type: INT, Flags: PUBLIC
    ITEM_FIELD_DURABILITY                     = OBJECT_END + 0x0036, // Size: 1, Type: INT, Flags: OWNER, ITEM_OWNER
    ITEM_FIELD_MAXDURABILITY                  = OBJECT_END + 0x0037, // Size: 1, Type: INT, Flags: OWNER, ITEM_OWNER
    ITEM_FIELD_CREATE_PLAYED_TIME             = OBJECT_END + 0x0038, // Size: 1, Type: INT, Flags: PUBLIC
    ITEM_FIELD_PAD                            = OBJECT_END + 0x0039, // Size: 1, Type: INT, Flags: NONE
    ITEM_END                                  = OBJECT_END + 0x003A,
};

enum EContainerFields
{
    CONTAINER_FIELD_NUM_SLOTS                 = ITEM_END + 0x0000, // Size: 1, Type: INT, Flags: PUBLIC
    CONTAINER_ALIGN_PAD                       = ITEM_END + 0x0001, // Size: 1, Type: BYTES, Flags: NONE
    CONTAINER_FIELD_SLOT_1                    = ITEM_END + 0x0002, // Size: 72, Type: LONG, Flags: PUBLIC
    CONTAINER_END                             = ITEM_END + 0x004A,
};

enum EUnitFields
{
    UNIT_FIELD_CHARM                          = OBJECT_END + 0x0000, // Size: 2, Type: LONG, Flags: PUBLIC
    UNIT_FIELD_SUMMON                         = OBJECT_END + 0x0002, // Size: 2, Type: LONG, Flags: PUBLIC
    UNIT_FIELD_CRITTER                        = OBJECT_END + 0x0004, // Size: 2, Type: LONG, Flags: PRIVATE
    UNIT_FIELD_CHARMEDBY                      = OBJECT_END + 0x0006, // Size: 2, Type: LONG, Flags: PUBLIC
    UNIT_FIELD_SUMMONEDBY                     = OBJECT_END + 0x0008, // Size: 2, Type: LONG, Flags: PUBLIC
    UNIT_FIELD_CREATEDBY                      = OBJECT_END + 0x000A, // Size: 2, Type: LONG, Flags: PUBLIC
    UNIT_FIELD_TARGET                         = OBJECT_END + 0x000C, // Size: 2, Type: LONG, Flags: PUBLIC
    UNIT_FIELD_CHANNEL_OBJECT                 = OBJECT_END + 0x000E, // Size: 2, Type: LONG, Flags: PUBLIC
    UNIT_CHANNEL_SPELL                        = OBJECT_END + 0x0010, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_BYTES_0                        = OBJECT_END + 0x0011, // Size: 1, Type: BYTES, Flags: PUBLIC
    UNIT_FIELD_HEALTH                         = OBJECT_END + 0x0012, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER1                         = OBJECT_END + 0x0013, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER2                         = OBJECT_END + 0x0014, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER3                         = OBJECT_END + 0x0015, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER4                         = OBJECT_END + 0x0016, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER5                         = OBJECT_END + 0x0017, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER6                         = OBJECT_END + 0x0018, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER7                         = OBJECT_END + 0x0019, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXHEALTH                      = OBJECT_END + 0x001A, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXPOWER1                      = OBJECT_END + 0x001B, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXPOWER2                      = OBJECT_END + 0x001C, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXPOWER3                      = OBJECT_END + 0x001D, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXPOWER4                      = OBJECT_END + 0x001E, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXPOWER5                      = OBJECT_END + 0x001F, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXPOWER6                      = OBJECT_END + 0x0020, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MAXPOWER7                      = OBJECT_END + 0x0021, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_POWER_REGEN_FLAT_MODIFIER      = OBJECT_END + 0x0022, // Size: 7, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POWER_REGEN_INTERRUPTED_FLAT_MODIFIER = OBJECT_END + 0x0029, // Size: 7, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_LEVEL                          = OBJECT_END + 0x0030, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_FACTIONTEMPLATE                = OBJECT_END + 0x0031, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_VIRTUAL_ITEM_SLOT_ID                 = OBJECT_END + 0x0032, // Size: 3, Type: INT, Flags: PUBLIC
    UNIT_FIELD_FLAGS                          = OBJECT_END + 0x0035, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_FLAGS_2                        = OBJECT_END + 0x0036, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_AURASTATE                      = OBJECT_END + 0x0037, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_BASEATTACKTIME                 = OBJECT_END + 0x0038, // Size: 2, Type: INT, Flags: PUBLIC
    UNIT_FIELD_RANGEDATTACKTIME               = OBJECT_END + 0x003A, // Size: 1, Type: INT, Flags: PRIVATE
    UNIT_FIELD_BOUNDINGRADIUS                 = OBJECT_END + 0x003B, // Size: 1, Type: FLOAT, Flags: PUBLIC
    UNIT_FIELD_COMBATREACH                    = OBJECT_END + 0x003C, // Size: 1, Type: FLOAT, Flags: PUBLIC
    UNIT_FIELD_DISPLAYID                      = OBJECT_END + 0x003D, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_NATIVEDISPLAYID                = OBJECT_END + 0x003E, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MOUNTDISPLAYID                 = OBJECT_END + 0x003F, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_MINDAMAGE                      = OBJECT_END + 0x0040, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER, PARTY_LEADER
    UNIT_FIELD_MAXDAMAGE                      = OBJECT_END + 0x0041, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER, PARTY_LEADER
    UNIT_FIELD_MINOFFHANDDAMAGE               = OBJECT_END + 0x0042, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER, PARTY_LEADER
    UNIT_FIELD_MAXOFFHANDDAMAGE               = OBJECT_END + 0x0043, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER, PARTY_LEADER
    UNIT_FIELD_BYTES_1                        = OBJECT_END + 0x0044, // Size: 1, Type: BYTES, Flags: PUBLIC
    UNIT_FIELD_PETNUMBER                      = OBJECT_END + 0x0045, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_PET_NAME_TIMESTAMP             = OBJECT_END + 0x0046, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_PETEXPERIENCE                  = OBJECT_END + 0x0047, // Size: 1, Type: INT, Flags: OWNER
    UNIT_FIELD_PETNEXTLEVELEXP                = OBJECT_END + 0x0048, // Size: 1, Type: INT, Flags: OWNER
    UNIT_DYNAMIC_FLAGS                        = OBJECT_END + 0x0049, // Size: 1, Type: INT, Flags: DYNAMIC
    UNIT_MOD_CAST_SPEED                       = OBJECT_END + 0x004A, // Size: 1, Type: FLOAT, Flags: PUBLIC
    UNIT_CREATED_BY_SPELL                     = OBJECT_END + 0x004B, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_NPC_FLAGS                            = OBJECT_END + 0x004C, // Size: 1, Type: INT, Flags: DYNAMIC
    UNIT_NPC_EMOTESTATE                       = OBJECT_END + 0x004D, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_STAT0                          = OBJECT_END + 0x004E, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_STAT1                          = OBJECT_END + 0x004F, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_STAT2                          = OBJECT_END + 0x0050, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_STAT3                          = OBJECT_END + 0x0051, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_STAT4                          = OBJECT_END + 0x0052, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POSSTAT0                       = OBJECT_END + 0x0053, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POSSTAT1                       = OBJECT_END + 0x0054, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POSSTAT2                       = OBJECT_END + 0x0055, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POSSTAT3                       = OBJECT_END + 0x0056, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POSSTAT4                       = OBJECT_END + 0x0057, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_NEGSTAT0                       = OBJECT_END + 0x0058, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_NEGSTAT1                       = OBJECT_END + 0x0059, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_NEGSTAT2                       = OBJECT_END + 0x005A, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_NEGSTAT3                       = OBJECT_END + 0x005B, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_NEGSTAT4                       = OBJECT_END + 0x005C, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_RESISTANCES                    = OBJECT_END + 0x005D, // Size: 7, Type: INT, Flags: PRIVATE, OWNER, PARTY_LEADER
    UNIT_FIELD_RESISTANCEBUFFMODSPOSITIVE     = OBJECT_END + 0x0064, // Size: 7, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_RESISTANCEBUFFMODSNEGATIVE     = OBJECT_END + 0x006B, // Size: 7, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_BASE_MANA                      = OBJECT_END + 0x0072, // Size: 1, Type: INT, Flags: PUBLIC
    UNIT_FIELD_BASE_HEALTH                    = OBJECT_END + 0x0073, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_BYTES_2                        = OBJECT_END + 0x0074, // Size: 1, Type: BYTES, Flags: PUBLIC
    UNIT_FIELD_ATTACK_POWER                   = OBJECT_END + 0x0075, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_ATTACK_POWER_MODS              = OBJECT_END + 0x0076, // Size: 1, Type: TWO_SHORT, Flags: PRIVATE, OWNER
    UNIT_FIELD_ATTACK_POWER_MULTIPLIER        = OBJECT_END + 0x0077, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_RANGED_ATTACK_POWER            = OBJECT_END + 0x0078, // Size: 1, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_RANGED_ATTACK_POWER_MODS       = OBJECT_END + 0x0079, // Size: 1, Type: TWO_SHORT, Flags: PRIVATE, OWNER
    UNIT_FIELD_RANGED_ATTACK_POWER_MULTIPLIER = OBJECT_END + 0x007A, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_MINRANGEDDAMAGE                = OBJECT_END + 0x007B, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_MAXRANGEDDAMAGE                = OBJECT_END + 0x007C, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POWER_COST_MODIFIER            = OBJECT_END + 0x007D, // Size: 7, Type: INT, Flags: PRIVATE, OWNER
    UNIT_FIELD_POWER_COST_MULTIPLIER          = OBJECT_END + 0x0084, // Size: 7, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_MAXHEALTHMODIFIER              = OBJECT_END + 0x008B, // Size: 1, Type: FLOAT, Flags: PRIVATE, OWNER
    UNIT_FIELD_HOVERHEIGHT                    = OBJECT_END + 0x008C, // Size: 1, Type: FLOAT, Flags: PUBLIC
    UNIT_FIELD_PADDING                        = OBJECT_END + 0x008D, // Size: 1, Type: INT, Flags: NONE
    UNIT_END                                  = OBJECT_END + 0x008E,

    PLAYER_DUEL_ARBITER                       = UNIT_END + 0x0000, // Size: 2, Type: LONG, Flags: PUBLIC
    PLAYER_FLAGS                              = UNIT_END + 0x0002, // Size: 1, Type: INT, Flags: PUBLIC
    PLAYER_GUILDID                            = UNIT_END + 0x0003, // Size: 1, Type: INT, Flags: PUBLIC
    PLAYER_GUILDRANK                          = UNIT_END + 0x0004, // Size: 1, Type: INT, Flags: PUBLIC
    PLAYER_BYTES                              = UNIT_END + 0x0005, // Size: 1, Type: BYTES, Flags: PUBLIC
    PLAYER_BYTES_2                            = UNIT_END + 0x0006, // Size: 1, Type: BYTES, Flags: PUBLIC
    PLAYER_BYTES_3                            = UNIT_END + 0x0007, // Size: 1, Type: BYTES, Flags: PUBLIC
    PLAYER_DUEL_TEAM                          = UNIT_END + 0x0008, // Size: 1, Type: INT, Flags: PUBLIC
    PLAYER_GUILD_TIMESTAMP                    = UNIT_END + 0x0009, // Size: 1, Type: INT, Flags: PUBLIC
    PLAYER_QUEST_LOG                          = UNIT_END + 0x000A, // Size: 25, Type: INT, Flags: PARTY_MEMBER
    PLAYER_VISIBLE_ITEM                       = UNIT_END + 0x0087, // Size: 19, Type: INT, Flags: PUBLIC
    PLAYER_CHOSEN_TITLE                       = UNIT_END + 0x00AD, // Size: 1, Type: INT, Flags: PUBLIC
    PLAYER_FAKE_INEBRIATION                   = UNIT_END + 0x00AE, // Size: 1, Type: INT, Flags: PUBLIC
    PLAYER_FIELD_PAD_0                        = UNIT_END + 0x00AF, // Size: 1, Type: INT, Flags: NONE
    PLAYER_FIELD_INV_SLOT_HEAD                = UNIT_END + 0x00B0, // Size: 46, Type: LONG, Flags: PRIVATE
    PLAYER_FIELD_PACK_SLOT_1                  = UNIT_END + 0x00DE, // Size: 32, Type: LONG, Flags: PRIVATE
    PLAYER_FIELD_BANK_SLOT_1                  = UNIT_END + 0x00FE, // Size: 56, Type: LONG, Flags: PRIVATE
    PLAYER_FIELD_BANKBAG_SLOT_1               = UNIT_END + 0x0136, // Size: 14, Type: LONG, Flags: PRIVATE
    PLAYER_FIELD_VENDORBUYBACK_SLOT_1         = UNIT_END + 0x0144, // Size: 24, Type: LONG, Flags: PRIVATE
    PLAYER_FIELD_KEYRING_SLOT_1               = UNIT_END + 0x015C, // Size: 64, Type: LONG, Flags: PRIVATE
    PLAYER_FIELD_CURRENCYTOKEN_SLOT_1         = UNIT_END + 0x019C, // Size: 64, Type: LONG, Flags: PRIVATE
    PLAYER_FARSIGHT                           = UNIT_END + 0x01DC, // Size: 2, Type: LONG, Flags: PRIVATE
    PLAYER__FIELD_KNOWN_TITLES                = UNIT_END + 0x01DE, // Size: 2, Type: LONG, Flags: PRIVATE
    PLAYER__FIELD_KNOWN_TITLES1               = UNIT_END + 0x01E0, // Size: 2, Type: LONG, Flags: PRIVATE
    PLAYER__FIELD_KNOWN_TITLES2               = UNIT_END + 0x01E2, // Size: 2, Type: LONG, Flags: PRIVATE
    PLAYER_FIELD_KNOWN_CURRENCIES             = UNIT_END + 0x01E4, // Size: 2, Type: LONG, Flags: PRIVATE
    PLAYER_XP                                 = UNIT_END + 0x01E6, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_NEXT_LEVEL_XP                      = UNIT_END + 0x01E7, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_SKILL_INFO_1_1                     = UNIT_END + 0x01E8, // Size: 384, Type: TWO_SHORT, Flags: PRIVATE
    PLAYER_CHARACTER_POINTS1                  = UNIT_END + 0x0368, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_CHARACTER_POINTS2                  = UNIT_END + 0x0369, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_TRACK_CREATURES                    = UNIT_END + 0x036A, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_TRACK_RESOURCES                    = UNIT_END + 0x036B, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_BLOCK_PERCENTAGE                   = UNIT_END + 0x036C, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_DODGE_PERCENTAGE                   = UNIT_END + 0x036D, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_PARRY_PERCENTAGE                   = UNIT_END + 0x036E, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_EXPERTISE                          = UNIT_END + 0x036F, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_OFFHAND_EXPERTISE                  = UNIT_END + 0x0370, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_CRIT_PERCENTAGE                    = UNIT_END + 0x0371, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_RANGED_CRIT_PERCENTAGE             = UNIT_END + 0x0372, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_OFFHAND_CRIT_PERCENTAGE            = UNIT_END + 0x0373, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_SPELL_CRIT_PERCENTAGE1             = UNIT_END + 0x0374, // Size: 7, Type: FLOAT, Flags: PRIVATE
    PLAYER_SHIELD_BLOCK                       = UNIT_END + 0x037B, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_SHIELD_BLOCK_CRIT_PERCENTAGE       = UNIT_END + 0x037C, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_EXPLORED_ZONES_1                   = UNIT_END + 0x037D, // Size: 128, Type: BYTES, Flags: PRIVATE
    PLAYER_REST_STATE_EXPERIENCE              = UNIT_END + 0x03FD, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_COINAGE                      = UNIT_END + 0x03FE, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_MOD_DAMAGE_DONE_POS          = UNIT_END + 0x03FF, // Size: 7, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_MOD_DAMAGE_DONE_NEG          = UNIT_END + 0x0406, // Size: 7, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_MOD_DAMAGE_DONE_PCT          = UNIT_END + 0x040D, // Size: 7, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_MOD_HEALING_DONE_POS         = UNIT_END + 0x0414, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_MOD_HEALING_PCT              = UNIT_END + 0x0415, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_FIELD_MOD_HEALING_DONE_PCT         = UNIT_END + 0x0416, // Size: 1, Type: FLOAT, Flags: PRIVATE
    PLAYER_FIELD_MOD_TARGET_RESISTANCE        = UNIT_END + 0x0417, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_MOD_TARGET_PHYSICAL_RESISTANCE = UNIT_END + 0x0418, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_BYTES                        = UNIT_END + 0x0419, // Size: 1, Type: BYTES, Flags: PRIVATE
    PLAYER_AMMO_ID                            = UNIT_END + 0x041A, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_SELF_RES_SPELL                     = UNIT_END + 0x041B, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_PVP_MEDALS                   = UNIT_END + 0x041C, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_BUYBACK_PRICE_1              = UNIT_END + 0x041D, // Size: 12, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_BUYBACK_TIMESTAMP_1          = UNIT_END + 0x0429, // Size: 12, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_KILLS                        = UNIT_END + 0x0435, // Size: 1, Type: TWO_SHORT, Flags: PRIVATE
    PLAYER_FIELD_TODAY_CONTRIBUTION           = UNIT_END + 0x0436, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_YESTERDAY_CONTRIBUTION       = UNIT_END + 0x0437, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_LIFETIME_HONORBALE_KILLS     = UNIT_END + 0x0438, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_BYTES2                       = UNIT_END + 0x0439, // Size: 1, Type: 6, Flags: PRIVATE
    PLAYER_FIELD_WATCHED_FACTION_INDEX        = UNIT_END + 0x043A, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_COMBAT_RATING_1              = UNIT_END + 0x043B, // Size: 25, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_ARENA_TEAM_INFO_1_1          = UNIT_END + 0x0454, // Size: 21, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_HONOR_CURRENCY               = UNIT_END + 0x0469, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_ARENA_CURRENCY               = UNIT_END + 0x046A, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_MAX_LEVEL                    = UNIT_END + 0x046B, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_DAILY_QUESTS_1               = UNIT_END + 0x046C, // Size: 25, Type: INT, Flags: PRIVATE
    PLAYER_RUNE_REGEN_1                       = UNIT_END + 0x0485, // Size: 4, Type: FLOAT, Flags: PRIVATE
    PLAYER_NO_REAGENT_COST_1                  = UNIT_END + 0x0489, // Size: 3, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_GLYPH_SLOTS_1                = UNIT_END + 0x048C, // Size: 6, Type: INT, Flags: PRIVATE
    PLAYER_FIELD_GLYPHS_1                     = UNIT_END + 0x0492, // Size: 6, Type: INT, Flags: PRIVATE
    PLAYER_GLYPHS_ENABLED                     = UNIT_END + 0x0498, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_PET_SPELL_POWER                    = UNIT_END + 0x0499, // Size: 1, Type: INT, Flags: PRIVATE
    PLAYER_END                                = UNIT_END + 0x049A,
};

enum EGameObjectFields
{
    OBJECT_FIELD_CREATED_BY                   = OBJECT_END + 0x0000, // Size: 2, Type: LONG, Flags: PUBLIC
    GAMEOBJECT_DISPLAYID                      = OBJECT_END + 0x0002, // Size: 1, Type: INT, Flags: PUBLIC
    GAMEOBJECT_FLAGS                          = OBJECT_END + 0x0003, // Size: 1, Type: INT, Flags: PUBLIC
    GAMEOBJECT_PARENTROTATION                 = OBJECT_END + 0x0004, // Size: 4, Type: FLOAT, Flags: PUBLIC
    GAMEOBJECT_DYNAMIC                        = OBJECT_END + 0x0008, // Size: 1, Type: TWO_SHORT, Flags: DYNAMIC
    GAMEOBJECT_FACTION                        = OBJECT_END + 0x0009, // Size: 1, Type: INT, Flags: PUBLIC
    GAMEOBJECT_LEVEL                          = OBJECT_END + 0x000A, // Size: 1, Type: INT, Flags: PUBLIC
    GAMEOBJECT_BYTES_1                        = OBJECT_END + 0x000B, // Size: 1, Type: BYTES, Flags: PUBLIC
    GAMEOBJECT_END                            = OBJECT_END + 0x000C,
};

enum EDynamicObjectFields
{
    DYNAMICOBJECT_CASTER                      = OBJECT_END + 0x0000, // Size: 2, Type: LONG, Flags: PUBLIC
    DYNAMICOBJECT_BYTES                       = OBJECT_END + 0x0002, // Size: 1, Type: BYTES, Flags: PUBLIC
    DYNAMICOBJECT_SPELLID                     = OBJECT_END + 0x0003, // Size: 1, Type: INT, Flags: PUBLIC
    DYNAMICOBJECT_RADIUS                      = OBJECT_END + 0x0004, // Size: 1, Type: FLOAT, Flags: PUBLIC
    DYNAMICOBJECT_CASTTIME                    = OBJECT_END + 0x0005, // Size: 1, Type: INT, Flags: PUBLIC
    DYNAMICOBJECT_END                         = OBJECT_END + 0x0006,
};

enum ECorpseFields
{
    CORPSE_FIELD_OWNER                        = OBJECT_END + 0x0000, // Size: 2, Type: LONG, Flags: PUBLIC
    CORPSE_FIELD_PARTY                        = OBJECT_END + 0x0002, // Size: 2, Type: LONG, Flags: PUBLIC
    CORPSE_FIELD_DISPLAY_ID                   = OBJECT_END + 0x0004, // Size: 1, Type: INT, Flags: PUBLIC
    CORPSE_FIELD_ITEM                         = OBJECT_END + 0x0005, // Size: 19, Type: INT, Flags: PUBLIC
    CORPSE_FIELD_BYTES_1                      = OBJECT_END + 0x0018, // Size: 1, Type: BYTES, Flags: PUBLIC
    CORPSE_FIELD_BYTES_2                      = OBJECT_END + 0x0019, // Size: 1, Type: BYTES, Flags: PUBLIC
    CORPSE_FIELD_GUILD                        = OBJECT_END + 0x001A, // Size: 1, Type: INT, Flags: PUBLIC
    CORPSE_FIELD_FLAGS                        = OBJECT_END + 0x001B, // Size: 1, Type: INT, Flags: PUBLIC
    CORPSE_FIELD_DYNAMIC_FLAGS                = OBJECT_END + 0x001C, // Size: 1, Type: INT, Flags: DYNAMIC
    CORPSE_FIELD_PAD                          = OBJECT_END + 0x001D, // Size: 1, Type: INT, Flags: NONE
    CORPSE_END                                = OBJECT_END + 0x001E,
};
#endif
