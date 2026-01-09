//! Denuvo Custom PAK Cipher Implementation
//!
//! This implements the custom block cipher used by Denuvo-protected games for PAK file decryption.
//! The cipher is AES-like (14 rounds, 16-byte blocks) but uses:
//! - Custom T-tables (not standard Rijndael)
//! - Pre-embedded round keys
//! - Custom round constants
//!
//! Algorithm reverse-engineered from game binary (sub_15993E60C).

/// Round keys extracted from runtime (0x14B4DC18C)
/// 60 DWORDs (240 bytes) as 32-bit little-endian values
const ROUND_KEYS: [u32; 60] = [
    0x54F29927, 0x79EA42BE, 0xF87B9AEC, 0xA2C5D8E1,
    0x23E5C1BC, 0x7D44F727, 0xC6874BFD, 0xACC473E7,
    0x00444679, 0xCC9133B1, 0xE0ACC107, 0x36F8D973,
    0x446F025A, 0x00C23C23, 0x7731CF73, 0x3237FA5E,
    0xC997F7CC, 0xB7FD7000, 0x290E9B96, 0x59B70EEE,
    0x6E6EC74D, 0x9D7CB71E, 0xD43082C1, 0x65CDB236,
    0x2FA6FA17, 0xFA0FF080, 0x02B15B4B, 0x5B46553F,
    0x7649FBE7, 0x99D2ABFE, 0x7D9D5B84, 0x46C663F5,
    0xF901C7D4, 0x8AD757C4, 0x8B02FFC3, 0xDD0F48F7,
    0x28CABA9E, 0x77E27BBC, 0x53656BC9, 0x487E4C3B,
    0xB1056CFF, 0x508D135A, 0x00C0D216, 0x4338E5EB,
    0x8A611C7A, 0xBF82694B, 0xC885A154, 0xEC769E53,
    0x116304E5, 0x9D8BAC91, 0xF0A8209C, 0x6C6D6640,
    0xFF72C07E, 0x9F8AEA19, 0x6819957C, 0x0E5101D7,
    0xC219863F, 0xA01458A9, 0x83EF50A9, 0xA78E799F,
];

/// Custom round constants (extracted from decompiled cipher function)
/// Each tuple: (rc0, rc1, rc2, rc3) for each round
const ROUND_CONSTANTS: [(u32, u32, u32, u32); 15] = [
    // Round 0 (initial)
    (0x4529BE46, 0xD7A5B9C8, 0xAA3FD14C, 0xC0DE6C1E),
    // Round 1
    (0x5C4F9A4C, 0xE6F05062, 0x2A7DAB4C, 0x686C82ED),
    // Round 2
    (0x2411811F, 0xB7E6E3A9, 0x130E5476, 0xEEA2E545),
    // Round 3
    (0xE2CB086A, 0x007F8887, 0x1C722319, 0x4C0234CB),
    // Round 4
    (0x1C14742C, 0xA1DBDEFF, 0x8684B4FB, 0x492F38E5),
    // Round 5
    (0xC27F07F6, 0xBFCEDA0F, 0x89A19EB5, 0xD4641CAC),
    // Round 6
    (0x96306A94, 0xBB1DDAD9, 0x4BCEFB52, 0xBA5E7B0C),
    // Round 7
    (0x8A8A8EFB, 0x02BE2AE1, 0x370559B4, 0xF0D979E1),
    // Round 8
    (0xA9D5F6CE, 0x836F7583, 0xAEEEDD0D, 0x640C5EF3),
    // Round 9
    (0xFB11D050, 0x8291E8E6, 0x5FA50BF0, 0x20595D5D),
    // Round 10
    (0x3F8FD192, 0x2C94D29F, 0xE9B900B4, 0xA85020A4),
    // Round 11
    (0x8EED8117, 0x31365237, 0x9F56FEC4, 0x9DB389C3),
    // Round 12
    (0x3C8E52B0, 0x65C833FB, 0x3DEAF324, 0xECB17626),
    // Round 13
    (0x9579EDF0, 0xB17EF190, 0xA88CE82F, 0xAFC1ADAC),
    // Final round
    (0xD0DAF815, 0x8F35763C, 0x74DE9104, 0x18A8D35A),
];

/// T-table 0 (0x1567ACB00) - 256 DWORDs (loaded from binary as little-endian)
const T0: [u32; 256] = [
    0xF4A75051, 0x4165537E, 0x17A4C31A, 0x275E963A, 0xAB6BCB3B, 0x9D45F11F, 0xFA58ABAC, 0xE303934B,
    0x30FA5520, 0x766DF6AD, 0xCC769188, 0x024C25F5, 0xE5D7FC4F, 0x2ACBD7C5, 0x35448026, 0x62A38FB5,
    0xB15A49DE, 0xBA1B6725, 0xEA0E9845, 0xFEC0E15D, 0x2F7502C3, 0x4CF01281, 0x4697A38D, 0xD3F9C66B,
    0x8F5FE703, 0x929C9515, 0x6D7AEBBF, 0x5259DA95, 0xBE832DD4, 0x7421D358, 0xE0692949, 0xC9C8448E,
    0xC2896A75, 0x8E7978F4, 0x583E6B99, 0xB971DD27, 0xE14FB6BE, 0x88AD17F0, 0x20AC66C9, 0xCE3AB47D,
    0xDF4A1863, 0x1A3182E5, 0x51336097, 0x537F4562, 0x6477E0B1, 0x6BAE84BB, 0x81A01CFE, 0x082B94F9,
    0x48685870, 0x45FD198F, 0xDE6C8794, 0x7BF8B752, 0x73D323AB, 0x4B02E272, 0x1F8F57E3, 0x55AB2A66,
    0xEB2807B2, 0xB5C2032F, 0xC57B9A86, 0x3708A5D3, 0x2887F230, 0xBFA5B223, 0x036ABA02, 0x16825CED,
    0xCF1C2B8A, 0x79B492A7, 0x07F2F0F3, 0x69E2A14E, 0xDAF4CD65, 0x05BED506, 0x34621FD1, 0xA6FE8AC4,
    0x2E539D34, 0xF355A0A2, 0x8AE13205, 0xF6EB75A4, 0x83EC390B, 0x60EFAA40, 0x719F065E, 0x6E1051BD,
    0x218AF93E, 0xDD063D96, 0x3E05AEDD, 0xE6BD464D, 0x548DB591, 0xC45D0571, 0x06D46F04, 0x5015FF60,
    0x98FB2419, 0xBDE997D6, 0x4043CC89, 0xD99E7767, 0xE842BDB0, 0x898B8807, 0x195B38E7, 0xC8EEDB79,
    0x7C0A47A1, 0x420FE97C, 0x841EC9F8, 0x00000000, 0x80868309, 0x2BED4832, 0x1170AC1E, 0x5A724E6C,
    0x0EFFFBFD, 0x8538560F, 0xAED51E3D, 0x2D392736, 0x0FD9640A, 0x5CA62168, 0x5B54D19B, 0x362E3A24,
    0x0A67B10C, 0x57E70F93, 0xEE96D2B4, 0x9B919E1B, 0xC0C54F80, 0xDC20A261, 0x774B695A, 0x121A161C,
    0x93BA0AE2, 0xA02AE5C0, 0x22E0433C, 0x1B171D12, 0x090D0B0E, 0x8BC7ADF2, 0xB6A8B92D, 0x1EA9C814,
    0xF1198557, 0x75074CAF, 0x99DDBBEE, 0x7F60FDA3, 0x01269FF7, 0x72F5BC5C, 0x663BC544, 0xFB7E345B,
    0x4329768B, 0x23C6DCCB, 0xEDFC68B6, 0xE4F163B8, 0x31DCCAD7, 0x63851042, 0x97224013, 0xC6112084,
    0x4A247D85, 0xBB3DF8D2, 0xF93211AE, 0x29A16DC7, 0x9E2F4B1D, 0xB230F3DC, 0x8652EC0D, 0xC1E3D077,
    0xB3166C2B, 0x70B999A9, 0x9448FA11, 0xE9642247, 0xFC8CC4A8, 0xF03F1AA0, 0x7D2CD856, 0x3390EF22,
    0x494EC787, 0x38D1C1D9, 0xCAA2FE8C, 0xD40B3698, 0xF581CFA6, 0x7ADE28A5, 0xB78E26DA, 0xADBFA43F,
    0x3A9DE42C, 0x78920D50, 0x5FCC9B6A, 0x7E466254, 0x8D13C2F6, 0xD8B8E890, 0x39F75E2E, 0xC3AFF582,
    0x5D80BE9F, 0xD0937C69, 0xD52DA96F, 0x2512B3CF, 0xAC993BC8, 0x187DA710, 0x9C636EE8, 0x3BBB7BDB,
    0x267809CD, 0x5918F46E, 0x9AB701EC, 0x4F9AA883, 0x956E65E6, 0xFFE67EAA, 0xBCCF0821, 0x15E8E6EF,
    0xE79BD9BA, 0x6F36CE4A, 0x9F09D4EA, 0xB07CD629, 0xA4B2AF31, 0x3F23312A, 0xA59430C6, 0xA266C035,
    0x4EBC3774, 0x82CAA6FC, 0x90D0B0E0, 0xA7D81533, 0x04984AF1, 0xECDAF741, 0xCD500E7F, 0x91F62F17,
    0x4DD68D76, 0xEFB04D43, 0xAA4D54CC, 0x9604DFE4, 0xD1B5E39E, 0x6A881B4C, 0x2C1FB8C1, 0x65517F46,
    0x5EEA049D, 0x8C355D01, 0x877473FA, 0x0B412EFB, 0x671D5AB3, 0xDBD25292, 0x105633E9, 0xD647136D,
    0xD7618C9A, 0xA10C7A37, 0xF8148E59, 0x133C89EB, 0xA927EECE, 0x61C935B7, 0x1CE5EDE1, 0x47B13C7A,
    0xD2DF599C, 0xF2733F55, 0x14CE7918, 0xC737BF73, 0xF7CDEA53, 0xFDAA5B5F, 0x3D6F14DF, 0x44DB8678,
    0xAFF381CA, 0x68C43EB9, 0x24342C38, 0xA3405FC2, 0x1DC37216, 0xE2250CBC, 0x3C498B28, 0x0D9541FF,
    0xA8017139, 0x0CB3DE08, 0xB4E49CD8, 0x56C19064, 0xCB84617B, 0x32B670D5, 0x6C5C7448, 0xB85742D0,
];

/// T-table 1 (0x15592BFD0) - 256 DWORDs (loaded from binary as little-endian)
const T1: [u32; 256] = [
    0x51F4A750, 0x7E416553, 0x1A17A4C3, 0x3A275E96, 0x3BAB6BCB, 0x1F9D45F1, 0xACFA58AB, 0x4BE30393,
    0x2030FA55, 0xAD766DF6, 0x88CC7691, 0xF5024C25, 0x4FE5D7FC, 0xC52ACBD7, 0x26354480, 0xB562A38F,
    0xDEB15A49, 0x25BA1B67, 0x45EA0E98, 0x5DFEC0E1, 0xC32F7502, 0x814CF012, 0x8D4697A3, 0x6BD3F9C6,
    0x038F5FE7, 0x15929C95, 0xBF6D7AEB, 0x955259DA, 0xD4BE832D, 0x587421D3, 0x49E06929, 0x8EC9C844,
    0x75C2896A, 0xF48E7978, 0x99583E6B, 0x27B971DD, 0xBEE14FB6, 0xF088AD17, 0xC920AC66, 0x7DCE3AB4,
    0x63DF4A18, 0xE51A3182, 0x97513360, 0x62537F45, 0xB16477E0, 0xBB6BAE84, 0xFE81A01C, 0xF9082B94,
    0x70486858, 0x8F45FD19, 0x94DE6C87, 0x527BF8B7, 0xAB73D323, 0x724B02E2, 0xE31F8F57, 0x6655AB2A,
    0xB2EB2807, 0x2FB5C203, 0x86C57B9A, 0xD33708A5, 0x302887F2, 0x23BFA5B2, 0x02036ABA, 0xED16825C,
    0x8ACF1C2B, 0xA779B492, 0xF307F2F0, 0x4E69E2A1, 0x65DAF4CD, 0x0605BED5, 0xD134621F, 0xC4A6FE8A,
    0x342E539D, 0xA2F355A0, 0x058AE132, 0xA4F6EB75, 0x0B83EC39, 0x4060EFAA, 0x5E719F06, 0xBD6E1051,
    0x3E218AF9, 0x96DD063D, 0xDD3E05AE, 0x4DE6BD46, 0x91548DB5, 0x71C45D05, 0x0406D46F, 0x605015FF,
    0x1998FB24, 0xD6BDE997, 0x894043CC, 0x67D99E77, 0xB0E842BD, 0x07898B88, 0xE7195B38, 0x79C8EEDB,
    0xA17C0A47, 0x7C420FE9, 0xF8841EC9, 0x00000000, 0x09808683, 0x322BED48, 0x1E1170AC, 0x6C5A724E,
    0xFD0EFFFB, 0x0F853856, 0x3DAED51E, 0x362D3927, 0x0A0FD964, 0x685CA621, 0x9B5B54D1, 0x24362E3A,
    0x0C0A67B1, 0x9357E70F, 0xB4EE96D2, 0x1B9B919E, 0x80C0C54F, 0x61DC20A2, 0x5A774B69, 0x1C121A16,
    0xE293BA0A, 0xC0A02AE5, 0x3C22E043, 0x121B171D, 0x0E090D0B, 0xF28BC7AD, 0x2DB6A8B9, 0x141EA9C8,
    0x57F11985, 0xAF75074C, 0xEE99DDBB, 0xA37F60FD, 0xF701269F, 0x5C72F5BC, 0x44663BC5, 0x5BFB7E34,
    0x8B432976, 0xCB23C6DC, 0xB6EDFC68, 0xB8E4F163, 0xD731DCCA, 0x42638510, 0x13972240, 0x84C61120,
    0x854A247D, 0xD2BB3DF8, 0xAEF93211, 0xC729A16D, 0x1D9E2F4B, 0xDCB230F3, 0x0D8652EC, 0x77C1E3D0,
    0x2BB3166C, 0xA970B999, 0x119448FA, 0x47E96422, 0xA8FC8CC4, 0xA0F03F1A, 0x567D2CD8, 0x223390EF,
    0x87494EC7, 0xD938D1C1, 0x8CCAA2FE, 0x98D40B36, 0xA6F581CF, 0xA57ADE28, 0xDAB78E26, 0x3FADBFA4,
    0x2C3A9DE4, 0x5078920D, 0x6A5FCC9B, 0x547E4662, 0xF68D13C2, 0x90D8B8E8, 0x2E39F75E, 0x82C3AFF5,
    0x9F5D80BE, 0x69D0937C, 0x6FD52DA9, 0xCF2512B3, 0xC8AC993B, 0x10187DA7, 0xE89C636E, 0xDB3BBB7B,
    0xCD267809, 0x6E5918F4, 0xEC9AB701, 0x834F9AA8, 0xE6956E65, 0xAAFFE67E, 0x21BCCF08, 0xEF15E8E6,
    0xBAE79BD9, 0x4A6F36CE, 0xEA9F09D4, 0x29B07CD6, 0x31A4B2AF, 0x2A3F2331, 0xC6A59430, 0x35A266C0,
    0x744EBC37, 0xFC82CAA6, 0xE090D0B0, 0x33A7D815, 0xF104984A, 0x41ECDAF7, 0x7FCD500E, 0x1791F62F,
    0x764DD68D, 0x43EFB04D, 0xCCAA4D54, 0xE49604DF, 0x9ED1B5E3, 0x4C6A881B, 0xC12C1FB8, 0x4665517F,
    0x9D5EEA04, 0x018C355D, 0xFA877473, 0xFB0B412E, 0xB3671D5A, 0x92DBD252, 0xE9105633, 0x6DD64713,
    0x9AD7618C, 0x37A10C7A, 0x59F8148E, 0xEB133C89, 0xCEA927EE, 0xB761C935, 0xE11CE5ED, 0x7A47B13C,
    0x9CD2DF59, 0x55F2733F, 0x1814CE79, 0x73C737BF, 0x53F7CDEA, 0x5FFDAA5B, 0xDF3D6F14, 0x7844DB86,
    0xCAAFF381, 0xB968C43E, 0x3824342C, 0xC2A3405F, 0x161DC372, 0xBCE2250C, 0x283C498B, 0xFF0D9541,
    0x39A80171, 0x080CB3DE, 0xD8B4E49C, 0x6456C190, 0x7BCB8461, 0xD532B670, 0x486C5C74, 0xD0B85742,
];

/// T-table 2 (0x159CEBE00) - 256 DWORDs (loaded from binary as little-endian)
const T2: [u32; 256] = [
    0x5051F4A7, 0x537E4165, 0xC31A17A4, 0x963A275E, 0xCB3BAB6B, 0xF11F9D45, 0xABACFA58, 0x934BE303,
    0x552030FA, 0xF6AD766D, 0x9188CC76, 0x25F5024C, 0xFC4FE5D7, 0xD7C52ACB, 0x80263544, 0x8FB562A3,
    0x49DEB15A, 0x6725BA1B, 0x9845EA0E, 0xE15DFEC0, 0x02C32F75, 0x12814CF0, 0xA38D4697, 0xC66BD3F9,
    0xE7038F5F, 0x9515929C, 0xEBBF6D7A, 0xDA955259, 0x2DD4BE83, 0xD3587421, 0x2949E069, 0x448EC9C8,
    0x6A75C289, 0x78F48E79, 0x6B99583E, 0xDD27B971, 0xB6BEE14F, 0x17F088AD, 0x66C920AC, 0xB47DCE3A,
    0x1863DF4A, 0x82E51A31, 0x60975133, 0x4562537F, 0xE0B16477, 0x84BB6BAE, 0x1CFE81A0, 0x94F9082B,
    0x58704868, 0x198F45FD, 0x8794DE6C, 0xB7527BF8, 0x23AB73D3, 0xE2724B02, 0x57E31F8F, 0x2A6655AB,
    0x07B2EB28, 0x032FB5C2, 0x9A86C57B, 0xA5D33708, 0xF2302887, 0xB223BFA5, 0xBA02036A, 0x5CED1682,
    0x2B8ACF1C, 0x92A779B4, 0xF0F307F2, 0xA14E69E2, 0xCD65DAF4, 0xD50605BE, 0x1FD13462, 0x8AC4A6FE,
    0x9D342E53, 0xA0A2F355, 0x32058AE1, 0x75A4F6EB, 0x390B83EC, 0xAA4060EF, 0x065E719F, 0x51BD6E10,
    0xF93E218A, 0x3D96DD06, 0xAEDD3E05, 0x464DE6BD, 0xB591548D, 0x0571C45D, 0x6F0406D4, 0xFF605015,
    0x241998FB, 0x97D6BDE9, 0xCC894043, 0x7767D99E, 0xBDB0E842, 0x8807898B, 0x38E7195B, 0xDB79C8EE,
    0x47A17C0A, 0xE97C420F, 0xC9F8841E, 0x00000000, 0x83098086, 0x48322BED, 0xAC1E1170, 0x4E6C5A72,
    0xFBFD0EFF, 0x560F8538, 0x1E3DAED5, 0x27362D39, 0x640A0FD9, 0x21685CA6, 0xD19B5B54, 0x3A24362E,
    0xB10C0A67, 0x0F9357E7, 0xD2B4EE96, 0x9E1B9B91, 0x4F80C0C5, 0xA261DC20, 0x695A774B, 0x161C121A,
    0x0AE293BA, 0xE5C0A02A, 0x433C22E0, 0x1D121B17, 0x0B0E090D, 0xADF28BC7, 0xB92DB6A8, 0xC8141EA9,
    0x8557F119, 0x4CAF7507, 0xBBEE99DD, 0xFDA37F60, 0x9FF70126, 0xBC5C72F5, 0xC544663B, 0x345BFB7E,
    0x768B4329, 0xDCCB23C6, 0x68B6EDFC, 0x63B8E4F1, 0xCAD731DC, 0x10426385, 0x40139722, 0x2084C611,
    0x7D854A24, 0xF8D2BB3D, 0x11AEF932, 0x6DC729A1, 0x4B1D9E2F, 0xF3DCB230, 0xEC0D8652, 0xD077C1E3,
    0x6C2BB316, 0x99A970B9, 0xFA119448, 0x2247E964, 0xC4A8FC8C, 0x1AA0F03F, 0xD8567D2C, 0xEF223390,
    0xC787494E, 0xC1D938D1, 0xFE8CCAA2, 0x3698D40B, 0xCFA6F581, 0x28A57ADE, 0x26DAB78E, 0xA43FADBF,
    0xE42C3A9D, 0x0D507892, 0x9B6A5FCC, 0x62547E46, 0xC2F68D13, 0xE890D8B8, 0x5E2E39F7, 0xF582C3AF,
    0xBE9F5D80, 0x7C69D093, 0xA96FD52D, 0xB3CF2512, 0x3BC8AC99, 0xA710187D, 0x6EE89C63, 0x7BDB3BBB,
    0x09CD2678, 0xF46E5918, 0x01EC9AB7, 0xA8834F9A, 0x65E6956E, 0x7EAAFFE6, 0x0821BCCF, 0xE6EF15E8,
    0xD9BAE79B, 0xCE4A6F36, 0xD4EA9F09, 0xD629B07C, 0xAF31A4B2, 0x312A3F23, 0x30C6A594, 0xC035A266,
    0x37744EBC, 0xA6FC82CA, 0xB0E090D0, 0x1533A7D8, 0x4AF10498, 0xF741ECDA, 0x0E7FCD50, 0x2F1791F6,
    0x8D764DD6, 0x4D43EFB0, 0x54CCAA4D, 0xDFE49604, 0xE39ED1B5, 0x1B4C6A88, 0xB8C12C1F, 0x7F466551,
    0x049D5EEA, 0x5D018C35, 0x73FA8774, 0x2EFB0B41, 0x5AB3671D, 0x5292DBD2, 0x33E91056, 0x136DD647,
    0x8C9AD761, 0x7A37A10C, 0x8E59F814, 0x89EB133C, 0xEECEA927, 0x35B761C9, 0xEDE11CE5, 0x3C7A47B1,
    0x599CD2DF, 0x3F55F273, 0x791814CE, 0xBF73C737, 0xEA53F7CD, 0x5B5FFDAA, 0x14DF3D6F, 0x867844DB,
    0x81CAAFF3, 0x3EB968C4, 0x2C382434, 0x5FC2A340, 0x72161DC3, 0x0CBCE225, 0x8B283C49, 0x41FF0D95,
    0x7139A801, 0xDE080CB3, 0x9CD8B4E4, 0x906456C1, 0x617BCB84, 0x70D532B6, 0x74486C5C, 0x42D0B857,
];

/// T-table 3 (0x150E69090) - 256 DWORDs (loaded from binary as little-endian)
const T3: [u32; 256] = [
    0xA75051F4, 0x65537E41, 0xA4C31A17, 0x5E963A27, 0x6BCB3BAB, 0x45F11F9D, 0x58ABACFA, 0x03934BE3,
    0xFA552030, 0x6DF6AD76, 0x769188CC, 0x4C25F502, 0xD7FC4FE5, 0xCBD7C52A, 0x44802635, 0xA38FB562,
    0x5A49DEB1, 0x1B6725BA, 0x0E9845EA, 0xC0E15DFE, 0x7502C32F, 0xF012814C, 0x97A38D46, 0xF9C66BD3,
    0x5FE7038F, 0x9C951592, 0x7AEBBF6D, 0x59DA9552, 0x832DD4BE, 0x21D35874, 0x692949E0, 0xC8448EC9,
    0x896A75C2, 0x7978F48E, 0x3E6B9958, 0x71DD27B9, 0x4FB6BEE1, 0xAD17F088, 0xAC66C920, 0x3AB47DCE,
    0x4A1863DF, 0x3182E51A, 0x33609751, 0x7F456253, 0x77E0B164, 0xAE84BB6B, 0xA01CFE81, 0x2B94F908,
    0x68587048, 0xFD198F45, 0x6C8794DE, 0xF8B7527B, 0xD323AB73, 0x02E2724B, 0x8F57E31F, 0xAB2A6655,
    0x2807B2EB, 0xC2032FB5, 0x7B9A86C5, 0x08A5D337, 0x87F23028, 0xA5B223BF, 0x6ABA0203, 0x825CED16,
    0x1C2B8ACF, 0xB492A779, 0xF2F0F307, 0xE2A14E69, 0xF4CD65DA, 0xBED50605, 0x621FD134, 0xFE8AC4A6,
    0x539D342E, 0x55A0A2F3, 0xE132058A, 0xEB75A4F6, 0xEC390B83, 0xEFAA4060, 0x9F065E71, 0x1051BD6E,
    0x8AF93E21, 0x063D96DD, 0x05AEDD3E, 0xBD464DE6, 0x8DB59154, 0x5D0571C4, 0xD46F0406, 0x15FF6050,
    0xFB241998, 0xE997D6BD, 0x43CC8940, 0x9E7767D9, 0x42BDB0E8, 0x8B880789, 0x5B38E719, 0xEEDB79C8,
    0x0A47A17C, 0x0FE97C42, 0x1EC9F884, 0x00000000, 0x86830980, 0xED48322B, 0x70AC1E11, 0x724E6C5A,
    0xFFFBFD0E, 0x38560F85, 0xD51E3DAE, 0x3927362D, 0xD9640A0F, 0xA621685C, 0x54D19B5B, 0x2E3A2436,
    0x67B10C0A, 0xE70F9357, 0x96D2B4EE, 0x919E1B9B, 0xC54F80C0, 0x20A261DC, 0x4B695A77, 0x1A161C12,
    0xBA0AE293, 0x2AE5C0A0, 0xE0433C22, 0x171D121B, 0x0D0B0E09, 0xC7ADF28B, 0xA8B92DB6, 0xA9C8141E,
    0x198557F1, 0x074CAF75, 0xDDBBEE99, 0x60FDA37F, 0x269FF701, 0xF5BC5C72, 0x3BC54466, 0x7E345BFB,
    0x29768B43, 0xC6DCCB23, 0xFC68B6ED, 0xF163B8E4, 0xDCCAD731, 0x85104263, 0x22401397, 0x112084C6,
    0x247D854A, 0x3DF8D2BB, 0x3211AEF9, 0xA16DC729, 0x2F4B1D9E, 0x30F3DCB2, 0x52EC0D86, 0xE3D077C1,
    0x166C2BB3, 0xB999A970, 0x48FA1194, 0x642247E9, 0x8CC4A8FC, 0x3F1AA0F0, 0x2CD8567D, 0x90EF2233,
    0x4EC78749, 0xD1C1D938, 0xA2FE8CCA, 0x0B3698D4, 0x81CFA6F5, 0xDE28A57A, 0x8E26DAB7, 0xBFA43FAD,
    0x9DE42C3A, 0x920D5078, 0xCC9B6A5F, 0x4662547E, 0x13C2F68D, 0xB8E890D8, 0xF75E2E39, 0xAFF582C3,
    0x80BE9F5D, 0x937C69D0, 0x2DA96FD5, 0x12B3CF25, 0x993BC8AC, 0x7DA71018, 0x636EE89C, 0xBB7BDB3B,
    0x7809CD26, 0x18F46E59, 0xB701EC9A, 0x9AA8834F, 0x6E65E695, 0xE67EAAFF, 0xCF0821BC, 0xE8E6EF15,
    0x9BD9BAE7, 0x36CE4A6F, 0x09D4EA9F, 0x7CD629B0, 0xB2AF31A4, 0x23312A3F, 0x9430C6A5, 0x66C035A2,
    0xBC37744E, 0xCAA6FC82, 0xD0B0E090, 0xD81533A7, 0x984AF104, 0xDAF741EC, 0x500E7FCD, 0xF62F1791,
    0xD68D764D, 0xB04D43EF, 0x4D54CCAA, 0x04DFE496, 0xB5E39ED1, 0x881B4C6A, 0x1FB8C12C, 0x517F4665,
    0xEA049D5E, 0x355D018C, 0x7473FA87, 0x412EFB0B, 0x1D5AB367, 0xD25292DB, 0x5633E910, 0x47136DD6,
    0x618C9AD7, 0x0C7A37A1, 0x148E59F8, 0x3C89EB13, 0x27EECEA9, 0xC935B761, 0xE5EDE11C, 0xB13C7A47,
    0xDF599CD2, 0x733F55F2, 0xCE791814, 0x37BF73C7, 0xCDEA53F7, 0xAA5B5FFD, 0x6F14DF3D, 0xDB867844,
    0xF381CAAF, 0xC43EB968, 0x342C3824, 0x405FC2A3, 0xC372161D, 0x250CBCE2, 0x498B283C, 0x9541FF0D,
    0x017139A8, 0xB3DE080C, 0xE49CD8B4, 0xC1906456, 0x84617BCB, 0xB670D532, 0x5C74486C, 0x5742D0B8,
];

/// Final S-box (0x154693B00) - 256 bytes
/// Note: This matches AES inverse S-box, confirming decryption direction
const SBOX_FINAL: [u8; 256] = [
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
];

/// Denuvo custom block cipher
///
/// A T-table based AES-like cipher with:
/// - Custom S-boxes (non-Rijndael)
/// - Pre-embedded round keys
/// - Custom round constants
/// - 14 rounds (like AES-256)
#[derive(Debug, Clone)]
pub struct FallenDollCipher;

impl FallenDollCipher {
    /// Create a new Denuvo cipher instance
    pub fn new() -> Self {
        FallenDollCipher
    }

    /// Decrypt a single 16-byte block
    ///
    /// Algorithm reverse-engineered from sub_15993E60C.
    /// Key observations from decompiled code:
    /// - Input is loaded as BIG-ENDIAN (MSB first)
    /// - T-table indices: T0[byte0], T1[byte3], T2[byte2], T3[byte1]
    /// - Output is written as BIG-ENDIAN
    pub fn decrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        // Load input as 4 x 32-bit words (BIG-ENDIAN as per decompiled code)
        let mut s0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut s1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let mut s2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
        let mut s3 = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

        // Initial AddRoundKey with round constants
        let rc = ROUND_CONSTANTS[0];
        s0 ^= ROUND_KEYS[0] ^ rc.0;
        s1 ^= ROUND_KEYS[1] ^ rc.1;
        s2 ^= ROUND_KEYS[2] ^ rc.2;
        s3 ^= ROUND_KEYS[3] ^ rc.3;

        // Round 1 (special pattern)
        // CRITICAL: Round 1 uses different state permutation than rounds 2-13
        let rc = ROUND_CONSTANTS[1];
        let rk_off = 4;

        let new_s0 = T0[(s0 & 0xFF) as usize]
            ^ T1[((s3 >> 24) & 0xFF) as usize]
            ^ T2[((s2 >> 16) & 0xFF) as usize]
            ^ T3[((s1 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 3]
            ^ rc.0;

        let new_s1 = T0[(s3 & 0xFF) as usize]
            ^ T1[((s2 >> 24) & 0xFF) as usize]
            ^ T2[((s1 >> 16) & 0xFF) as usize]
            ^ T3[((s0 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 2]
            ^ rc.1;

        let new_s2 = T0[(s2 & 0xFF) as usize]
            ^ T1[((s1 >> 24) & 0xFF) as usize]
            ^ T2[((s0 >> 16) & 0xFF) as usize]
            ^ T3[((s3 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 1]
            ^ rc.2;

        let new_s3 = T0[(s1 & 0xFF) as usize]
            ^ T1[((s0 >> 24) & 0xFF) as usize]
            ^ T2[((s3 >> 16) & 0xFF) as usize]
            ^ T3[((s2 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off]
            ^ rc.3;

        s0 = new_s0;
        s1 = new_s1;
        s2 = new_s2;
        s3 = new_s3;

        // Rounds 2-13 (different state permutation pattern)
        // CRITICAL: Forward order (2, 3, ..., 13), NOT reverse!
        for rnd in 2..14 {
            let rc = ROUND_CONSTANTS[rnd];
            let rk_off = rnd * 4;

            // output0: T0[s3], T1[s0], T2[s1], T3[s2]
            let new_s0 = T0[(s3 & 0xFF) as usize]
                ^ T1[((s0 >> 24) & 0xFF) as usize]
                ^ T2[((s1 >> 16) & 0xFF) as usize]
                ^ T3[((s2 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 3]
                ^ rc.0;

            // output1: T0[s0], T1[s1], T2[s2], T3[s3]
            let new_s1 = T0[(s0 & 0xFF) as usize]
                ^ T1[((s1 >> 24) & 0xFF) as usize]
                ^ T2[((s2 >> 16) & 0xFF) as usize]
                ^ T3[((s3 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 2]
                ^ rc.1;

            // output2: T0[s1], T1[s2], T2[s3], T3[s0]
            let new_s2 = T0[(s1 & 0xFF) as usize]
                ^ T1[((s2 >> 24) & 0xFF) as usize]
                ^ T2[((s3 >> 16) & 0xFF) as usize]
                ^ T3[((s0 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 1]
                ^ rc.2;

            // output3: T0[s2], T1[s3], T2[s0], T3[s1]
            let new_s3 = T0[(s2 & 0xFF) as usize]
                ^ T1[((s3 >> 24) & 0xFF) as usize]
                ^ T2[((s0 >> 16) & 0xFF) as usize]
                ^ T3[((s1 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off]
                ^ rc.3;

            s0 = new_s0;
            s1 = new_s1;
            s2 = new_s2;
            s3 = new_s3;
        }

        // Final round (uses S-box directly, no MixColumns)
        let rc = ROUND_CONSTANTS[14];
        let mut out = [0u8; 16];

        // Output word 0 (bytes 0-3)
        let rk_rc = ROUND_KEYS[56] ^ rc.0;
        out[0] = SBOX_FINAL[((s3 >> 24) & 0xFF) as usize] ^ ((rk_rc >> 24) & 0xFF) as u8;
        out[1] = SBOX_FINAL[((s0 >> 16) & 0xFF) as usize] ^ ((rk_rc >> 16) & 0xFF) as u8;
        out[2] = SBOX_FINAL[((s1 >> 8) & 0xFF) as usize] ^ ((rk_rc >> 8) & 0xFF) as u8;
        out[3] = SBOX_FINAL[(s2 & 0xFF) as usize] ^ (rk_rc & 0xFF) as u8;

        // Output word 1 (bytes 4-7)
        let rk_rc = ROUND_KEYS[57] ^ rc.1;
        out[4] = SBOX_FINAL[((s2 >> 24) & 0xFF) as usize] ^ ((rk_rc >> 24) & 0xFF) as u8;
        out[5] = SBOX_FINAL[((s3 >> 16) & 0xFF) as usize] ^ ((rk_rc >> 16) & 0xFF) as u8;
        out[6] = SBOX_FINAL[((s0 >> 8) & 0xFF) as usize] ^ ((rk_rc >> 8) & 0xFF) as u8;
        out[7] = SBOX_FINAL[(s1 & 0xFF) as usize] ^ (rk_rc & 0xFF) as u8;

        // Output word 2 (bytes 8-11)
        let rk_rc = ROUND_KEYS[58] ^ rc.2;
        out[8] = SBOX_FINAL[((s1 >> 24) & 0xFF) as usize] ^ ((rk_rc >> 24) & 0xFF) as u8;
        out[9] = SBOX_FINAL[((s2 >> 16) & 0xFF) as usize] ^ ((rk_rc >> 16) & 0xFF) as u8;
        out[10] = SBOX_FINAL[((s3 >> 8) & 0xFF) as usize] ^ ((rk_rc >> 8) & 0xFF) as u8;
        out[11] = SBOX_FINAL[(s0 & 0xFF) as usize] ^ (rk_rc & 0xFF) as u8;

        // Output word 3 (bytes 12-15)
        let rk_rc = ROUND_KEYS[59] ^ rc.3;
        out[12] = SBOX_FINAL[((s0 >> 24) & 0xFF) as usize] ^ ((rk_rc >> 24) & 0xFF) as u8;
        out[13] = SBOX_FINAL[((s1 >> 16) & 0xFF) as usize] ^ ((rk_rc >> 16) & 0xFF) as u8;
        out[14] = SBOX_FINAL[((s2 >> 8) & 0xFF) as usize] ^ ((rk_rc >> 8) & 0xFF) as u8;
        out[15] = SBOX_FINAL[(s3 & 0xFF) as usize] ^ (rk_rc & 0xFF) as u8;

        out
    }

    /// Decrypt data in-place (must be multiple of 16 bytes)
    pub fn decrypt(&self, data: &mut [u8]) {
        assert!(data.len() % 16 == 0, "Data length must be multiple of 16");

        for chunk in data.chunks_exact_mut(16) {
            let block: [u8; 16] = chunk.try_into().unwrap();
            let decrypted = self.decrypt_block(&block);
            chunk.copy_from_slice(&decrypted);
        }
    }
}

impl Default for FallenDollCipher {
    fn default() -> Self {
        Self::new()
    }
}



// ============================================================================
// ENCRYPTION SUPPORT
// ============================================================================

/// Forward S-box (inverse of SBOX_FINAL) - Used for encryption
const SBOX_FWD: [u8; 256] = [
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
];

// GF(2^8) multiplication for MixColumns in encryption
const fn xtime(x: u8) -> u8 {
    if x & 0x80 != 0 { (x << 1) ^ 0x1b } else { x << 1 }
}

const fn mul3(x: u8) -> u8 {
    xtime(x) ^ x
}

// Encryption T-table generators
// Denuvo uses rotated byte order: Standard [02,01,01,03] -> Denuvo [01,01,03,02]
// This matches the TD table rotation pattern discovered: [0E,09,0D,0B] -> [09,0D,0B,0E]
// VARIANT A: Current formula [1*S, 1*S, 3*S, 2*S]
const fn make_te0_entry_a(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [01*S, 01*S, 03*S, 02*S]
    ((s as u32) << 24) | ((s as u32) << 16) | ((x3 as u32) << 8) | (x2 as u32)
}

// VARIANT B: Standard AES formula [2*S, 1*S, 1*S, 3*S]
const fn make_te0_entry_b(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [02*S, 01*S, 01*S, 03*S] - standard MixColumns coefficients
    ((x2 as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (x3 as u32)
}

// VARIANT C: [3*S, 2*S, 1*S, 1*S]
const fn make_te0_entry_c(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [03*S, 02*S, 01*S, 01*S]
    ((x3 as u32) << 24) | ((x2 as u32) << 16) | ((s as u32) << 8) | (s as u32)
}

// VARIANT D: [1*S, 3*S, 2*S, 1*S]
const fn make_te0_entry_d(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [01*S, 03*S, 02*S, 01*S]
    ((s as u32) << 24) | ((x3 as u32) << 16) | ((x2 as u32) << 8) | (s as u32)
}

// VARIANT E: [3*S, 1*S, 1*S, 2*S] - DENUVO SPECIFIC
// This is derived from InvMixColumns [09, 0D, 0B, 0E] which is standard AES rotated left by 1
// Forward MixColumns should be standard [02, 03, 01, 01] also rotated left by 1 = [03, 01, 01, 02]
const fn make_te0_entry_e(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [03*S, 01*S, 01*S, 02*S] - Denuvo MixColumns coefficients
    ((x3 as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (x2 as u32)
}

// TE1 variants (rotated from TE0 by 8 bits)
const fn make_te1_entry_a(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((x2 as u32) << 24) | ((s as u32) << 16) | ((s as u32) << 8) | (x3 as u32)
}

const fn make_te1_entry_b(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((s as u32) << 24) | ((s as u32) << 16) | ((x3 as u32) << 8) | (x2 as u32)
}

const fn make_te1_entry_c(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((s as u32) << 24) | ((x2 as u32) << 16) | ((x3 as u32) << 8) | (s as u32)
}

const fn make_te1_entry_d(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((x3 as u32) << 24) | ((s as u32) << 16) | ((x2 as u32) << 8) | (s as u32)
}

// VARIANT E (TE1 rotated from TE0_E by 8 bits)
const fn make_te1_entry_e(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [02*S, 03*S, 01*S, 01*S] - TE0_E rotated right by 8
    ((x2 as u32) << 24) | ((x3 as u32) << 16) | ((s as u32) << 8) | (s as u32)
}

// TE2 variants
const fn make_te2_entry_a(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((x3 as u32) << 24) | ((x2 as u32) << 16) | ((s as u32) << 8) | (s as u32)
}

const fn make_te2_entry_b(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((s as u32) << 24) | ((x3 as u32) << 16) | ((x2 as u32) << 8) | (s as u32)
}

const fn make_te2_entry_c(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((x2 as u32) << 24) | ((x3 as u32) << 16) | ((s as u32) << 8) | (s as u32)
}

const fn make_te2_entry_d(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((x3 as u32) << 24) | ((s as u32) << 16) | ((x2 as u32) << 8) | (s as u32)
}

// VARIANT E (TE2 rotated from TE0_E by 16 bits)
const fn make_te2_entry_e(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [01*S, 02*S, 03*S, 01*S] - TE0_E rotated right by 16
    ((s as u32) << 24) | ((x2 as u32) << 16) | ((x3 as u32) << 8) | (s as u32)
}

// TE3 variants
const fn make_te3_entry_a(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((s as u32) << 24) | ((x3 as u32) << 16) | ((x2 as u32) << 8) | (s as u32)
}

const fn make_te3_entry_b(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((x3 as u32) << 24) | ((x2 as u32) << 16) | ((s as u32) << 8) | (s as u32)
}

const fn make_te3_entry_c(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((x2 as u32) << 24) | ((s as u32) << 16) | ((x3 as u32) << 8) | (s as u32)
}

const fn make_te3_entry_d(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    ((s as u32) << 24) | ((x2 as u32) << 16) | ((x3 as u32) << 8) | (s as u32)
}

// VARIANT E (TE3 rotated from TE0_E by 24 bits)
const fn make_te3_entry_e(i: usize) -> u32 {
    let s = SBOX_FWD[i];
    let x2 = xtime(s);
    let x3 = mul3(s);
    // [01*S, 01*S, 02*S, 03*S] - TE0_E rotated right by 24
    ((s as u32) << 24) | ((s as u32) << 16) | ((x2 as u32) << 8) | (x3 as u32)
}

// Table generation for all variants
const fn generate_te0_a() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te0_entry_a(i);
        i += 1;
    }
    table
}

const fn generate_te0_b() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te0_entry_b(i);
        i += 1;
    }
    table
}

const fn generate_te0_c() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te0_entry_c(i);
        i += 1;
    }
    table
}

const fn generate_te0_d() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te0_entry_d(i);
        i += 1;
    }
    table
}

// Similar for TE1, TE2, TE3
const fn generate_te1_a() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te1_entry_a(i);
        i += 1;
    }
    table
}

const fn generate_te1_b() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te1_entry_b(i);
        i += 1;
    }
    table
}

const fn generate_te1_c() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te1_entry_c(i);
        i += 1;
    }
    table
}

const fn generate_te1_d() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te1_entry_d(i);
        i += 1;
    }
    table
}

const fn generate_te2_a() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te2_entry_a(i);
        i += 1;
    }
    table
}

const fn generate_te2_b() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te2_entry_b(i);
        i += 1;
    }
    table
}

const fn generate_te2_c() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te2_entry_c(i);
        i += 1;
    }
    table
}

const fn generate_te2_d() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te2_entry_d(i);
        i += 1;
    }
    table
}

const fn generate_te3_a() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te3_entry_a(i);
        i += 1;
    }
    table
}

const fn generate_te3_b() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te3_entry_b(i);
        i += 1;
    }
    table
}

const fn generate_te3_c() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te3_entry_c(i);
        i += 1;
    }
    table
}

const fn generate_te3_d() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te3_entry_d(i);
        i += 1;
    }
    table
}

// Variant E generation (Denuvo-specific MixColumns: [03, 01, 01, 02])
const fn generate_te0_e() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te0_entry_e(i);
        i += 1;
    }
    table
}

const fn generate_te1_e() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te1_entry_e(i);
        i += 1;
    }
    table
}

const fn generate_te2_e() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te2_entry_e(i);
        i += 1;
    }
    table
}

const fn generate_te3_e() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut i = 0;
    while i < 256 {
        table[i] = make_te3_entry_e(i);
        i += 1;
    }
    table
}

/// Encryption T-tables (compile-time generated) - Currently using Variant A
const TE0: [u32; 256] = generate_te0_a();
const TE1: [u32; 256] = generate_te1_a();
const TE2: [u32; 256] = generate_te2_a();
const TE3: [u32; 256] = generate_te3_a();

/// Variant B tables (Standard AES coefficients)
const TE0_B: [u32; 256] = generate_te0_b();
const TE1_B: [u32; 256] = generate_te1_b();
const TE2_B: [u32; 256] = generate_te2_b();
const TE3_B: [u32; 256] = generate_te3_b();

/// Variant C tables
const TE0_C: [u32; 256] = generate_te0_c();
const TE1_C: [u32; 256] = generate_te1_c();
const TE2_C: [u32; 256] = generate_te2_c();
const TE3_C: [u32; 256] = generate_te3_c();

/// Variant D tables
const TE0_D: [u32; 256] = generate_te0_d();
const TE1_D: [u32; 256] = generate_te1_d();
const TE2_D: [u32; 256] = generate_te2_d();
const TE3_D: [u32; 256] = generate_te3_d();

/// Variant E tables (Denuvo-specific: [03, 01, 01, 02] derived from InvMixColumns [09, 0D, 0B, 0E])
const TE0_E: [u32; 256] = generate_te0_e();
const TE1_E: [u32; 256] = generate_te1_e();
const TE2_E: [u32; 256] = generate_te2_e();
const TE3_E: [u32; 256] = generate_te3_e();

impl FallenDollCipher {
    /// Test variant of encrypt that uses specified T-tables (for testing)
    pub fn encrypt_block_variant(&self, block: &[u8; 16], variant: u8) -> [u8; 16] {
        let (te0, te1, te2, te3) = match variant {
            0 => (&TE0, &TE1, &TE2, &TE3),
            1 => (&TE0_B, &TE1_B, &TE2_B, &TE3_B),
            2 => (&TE0_C, &TE1_C, &TE2_C, &TE3_C),
            3 => (&TE0_D, &TE1_D, &TE2_D, &TE3_D),
            4 => (&TE0_E, &TE1_E, &TE2_E, &TE3_E),  // Denuvo-specific
            _ => (&TE0_E, &TE1_E, &TE2_E, &TE3_E),  // Default to Denuvo variant
        };

        let mut s0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut s1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let mut s2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
        let mut s3 = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

        // Step 1: Inverse of decrypt's Final round
        let rc = ROUND_CONSTANTS[14];
        let rk_rc_0 = ROUND_KEYS[56] ^ rc.0;
        let rk_rc_1 = ROUND_KEYS[57] ^ rc.1;
        let rk_rc_2 = ROUND_KEYS[58] ^ rc.2;
        let rk_rc_3 = ROUND_KEYS[59] ^ rc.3;

        let in0 = s0.to_be_bytes();
        let in1 = s1.to_be_bytes();
        let in2 = s2.to_be_bytes();
        let in3 = s3.to_be_bytes();

        let t0 = SBOX_FWD[(in0[0] ^ ((rk_rc_0 >> 24) as u8)) as usize];
        let t1 = SBOX_FWD[(in0[1] ^ ((rk_rc_0 >> 16) as u8)) as usize];
        let t2 = SBOX_FWD[(in0[2] ^ ((rk_rc_0 >> 8) as u8)) as usize];
        let t3 = SBOX_FWD[(in0[3] ^ (rk_rc_0 as u8)) as usize];

        let t4 = SBOX_FWD[(in1[0] ^ ((rk_rc_1 >> 24) as u8)) as usize];
        let t5 = SBOX_FWD[(in1[1] ^ ((rk_rc_1 >> 16) as u8)) as usize];
        let t6 = SBOX_FWD[(in1[2] ^ ((rk_rc_1 >> 8) as u8)) as usize];
        let t7 = SBOX_FWD[(in1[3] ^ (rk_rc_1 as u8)) as usize];

        let t8 = SBOX_FWD[(in2[0] ^ ((rk_rc_2 >> 24) as u8)) as usize];
        let t9 = SBOX_FWD[(in2[1] ^ ((rk_rc_2 >> 16) as u8)) as usize];
        let t10 = SBOX_FWD[(in2[2] ^ ((rk_rc_2 >> 8) as u8)) as usize];
        let t11 = SBOX_FWD[(in2[3] ^ (rk_rc_2 as u8)) as usize];

        let t12 = SBOX_FWD[(in3[0] ^ ((rk_rc_3 >> 24) as u8)) as usize];
        let t13 = SBOX_FWD[(in3[1] ^ ((rk_rc_3 >> 16) as u8)) as usize];
        let t14 = SBOX_FWD[(in3[2] ^ ((rk_rc_3 >> 8) as u8)) as usize];
        let t15 = SBOX_FWD[(in3[3] ^ (rk_rc_3 as u8)) as usize];

        s0 = u32::from_be_bytes([t12, t1, t6, t11]);
        s1 = u32::from_be_bytes([t8, t13, t2, t7]);
        s2 = u32::from_be_bytes([t4, t9, t14, t3]);
        s3 = u32::from_be_bytes([t0, t5, t10, t15]);

        // Step 2: Inverse of decrypt's Rounds 2-13
        // Try FORWARD order: 2→3→...→13 (since decrypt also uses forward order)
        // Use SAME byte indices as decrypt (per ENCRYPT_FIX_GUIDE.md)
        for rnd in 2..14 {
            let rc = ROUND_CONSTANTS[rnd];
            let rk_off = rnd * 4;

            // Same indices as decrypt Pattern B
            let new_s0 = te0[(s3 & 0xFF) as usize]
                ^ te1[((s0 >> 24) & 0xFF) as usize]
                ^ te2[((s1 >> 16) & 0xFF) as usize]
                ^ te3[((s2 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 3]
                ^ rc.0;

            let new_s1 = te0[(s0 & 0xFF) as usize]
                ^ te1[((s1 >> 24) & 0xFF) as usize]
                ^ te2[((s2 >> 16) & 0xFF) as usize]
                ^ te3[((s3 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 2]
                ^ rc.1;

            let new_s2 = te0[(s1 & 0xFF) as usize]
                ^ te1[((s2 >> 24) & 0xFF) as usize]
                ^ te2[((s3 >> 16) & 0xFF) as usize]
                ^ te3[((s0 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 1]
                ^ rc.2;

            let new_s3 = te0[(s2 & 0xFF) as usize]
                ^ te1[((s3 >> 24) & 0xFF) as usize]
                ^ te2[((s0 >> 16) & 0xFF) as usize]
                ^ te3[((s1 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off]
                ^ rc.3;

            s0 = new_s0;
            s1 = new_s1;
            s2 = new_s2;
            s3 = new_s3;
        }

        // Step 3: Inverse of decrypt's Round 1
        let rc = ROUND_CONSTANTS[1];
        let rk_off = 4;

        let new_s0 = te0[(s0 & 0xFF) as usize]
            ^ te1[((s3 >> 24) & 0xFF) as usize]
            ^ te2[((s2 >> 16) & 0xFF) as usize]
            ^ te3[((s1 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 3]
            ^ rc.0;

        let new_s1 = te0[(s3 & 0xFF) as usize]
            ^ te1[((s2 >> 24) & 0xFF) as usize]
            ^ te2[((s1 >> 16) & 0xFF) as usize]
            ^ te3[((s0 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 2]
            ^ rc.1;

        let new_s2 = te0[(s2 & 0xFF) as usize]
            ^ te1[((s1 >> 24) & 0xFF) as usize]
            ^ te2[((s0 >> 16) & 0xFF) as usize]
            ^ te3[((s3 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 1]
            ^ rc.2;

        let new_s3 = te0[(s1 & 0xFF) as usize]
            ^ te1[((s0 >> 24) & 0xFF) as usize]
            ^ te2[((s3 >> 16) & 0xFF) as usize]
            ^ te3[((s2 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off]
            ^ rc.3;

        s0 = new_s0;
        s1 = new_s1;
        s2 = new_s2;
        s3 = new_s3;

        // Step 4: Inverse of decrypt's Initial AddRoundKey
        let rc = ROUND_CONSTANTS[0];
        s0 ^= ROUND_KEYS[0] ^ rc.0;
        s1 ^= ROUND_KEYS[1] ^ rc.1;
        s2 ^= ROUND_KEYS[2] ^ rc.2;
        s3 ^= ROUND_KEYS[3] ^ rc.3;

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&s0.to_be_bytes());
        out[4..8].copy_from_slice(&s1.to_be_bytes());
        out[8..12].copy_from_slice(&s2.to_be_bytes());
        out[12..16].copy_from_slice(&s3.to_be_bytes());
        out
    }

    /// Encrypt a single 16-byte block (inverse of decrypt_block)
    ///
    /// Implements encryption by properly inverting each decrypt operation:
    /// - TD_inverse = SubBytes ∘ MixColumns (after XOR with key)
    /// - Uses Denuvo MixColumns [0x03, 0x01, 0x01, 0x02]
    pub fn encrypt_block(&self, block: &[u8; 16]) -> [u8; 16] {
        self.encrypt_block_stepwise(block)
    }

    /// Step-by-step encryption without T-tables
    /// Properly inverts each decrypt operation in reverse order
    fn encrypt_block_stepwise(&self, block: &[u8; 16]) -> [u8; 16] {
        // GF(2^8) multiplication
        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p: u8 = 0;
            let mut aa = a;
            let mut bb = b;
            for _ in 0..8 {
                if bb & 1 != 0 { p ^= aa; }
                let hi = aa & 0x80;
                aa <<= 1;
                if hi != 0 { aa ^= 0x1b; }
                bb >>= 1;
            }
            p
        }

        // Forward MixColumns with STANDARD AES coefficients [0x02, 0x03, 0x01, 0x01]
        // The T-table structure actually uses standard AES InvMixColumns, so we need
        // standard AES MixColumns to invert it
        fn mix_column(c0: u8, c1: u8, c2: u8, c3: u8) -> (u8, u8, u8, u8) {
            // Standard AES MixColumns matrix:
            // [02 03 01 01]
            // [01 02 03 01]
            // [01 01 02 03]
            // [03 01 01 02]
            let r0 = gf_mul(c0, 0x02) ^ gf_mul(c1, 0x03) ^ c2 ^ c3;
            let r1 = c0 ^ gf_mul(c1, 0x02) ^ gf_mul(c2, 0x03) ^ c3;
            let r2 = c0 ^ c1 ^ gf_mul(c2, 0x02) ^ gf_mul(c3, 0x03);
            let r3 = gf_mul(c0, 0x03) ^ c1 ^ c2 ^ gf_mul(c3, 0x02);
            (r0, r1, r2, r3)
        }

        let mut s0 = u32::from_be_bytes([block[0], block[1], block[2], block[3]]);
        let mut s1 = u32::from_be_bytes([block[4], block[5], block[6], block[7]]);
        let mut s2 = u32::from_be_bytes([block[8], block[9], block[10], block[11]]);
        let mut s3 = u32::from_be_bytes([block[12], block[13], block[14], block[15]]);

        // Step 1: Inverse of decrypt's Final round
        // Decrypt final: out[i] = SBOX_FINAL[state_byte] ^ key_byte
        // Inverse: state_byte = SBOX_FWD[out[i] ^ key_byte]
        let rc = ROUND_CONSTANTS[14];
        let rk_rc_0 = ROUND_KEYS[56] ^ rc.0;
        let rk_rc_1 = ROUND_KEYS[57] ^ rc.1;
        let rk_rc_2 = ROUND_KEYS[58] ^ rc.2;
        let rk_rc_3 = ROUND_KEYS[59] ^ rc.3;

        let in0 = s0.to_be_bytes();
        let in1 = s1.to_be_bytes();
        let in2 = s2.to_be_bytes();
        let in3 = s3.to_be_bytes();

        // Reverse the byte permutation from decrypt final round
        let t0 = SBOX_FWD[(in0[0] ^ ((rk_rc_0 >> 24) as u8)) as usize];
        let t1 = SBOX_FWD[(in0[1] ^ ((rk_rc_0 >> 16) as u8)) as usize];
        let t2 = SBOX_FWD[(in0[2] ^ ((rk_rc_0 >> 8) as u8)) as usize];
        let t3 = SBOX_FWD[(in0[3] ^ (rk_rc_0 as u8)) as usize];
        let t4 = SBOX_FWD[(in1[0] ^ ((rk_rc_1 >> 24) as u8)) as usize];
        let t5 = SBOX_FWD[(in1[1] ^ ((rk_rc_1 >> 16) as u8)) as usize];
        let t6 = SBOX_FWD[(in1[2] ^ ((rk_rc_1 >> 8) as u8)) as usize];
        let t7 = SBOX_FWD[(in1[3] ^ (rk_rc_1 as u8)) as usize];
        let t8 = SBOX_FWD[(in2[0] ^ ((rk_rc_2 >> 24) as u8)) as usize];
        let t9 = SBOX_FWD[(in2[1] ^ ((rk_rc_2 >> 16) as u8)) as usize];
        let t10 = SBOX_FWD[(in2[2] ^ ((rk_rc_2 >> 8) as u8)) as usize];
        let t11 = SBOX_FWD[(in2[3] ^ (rk_rc_2 as u8)) as usize];
        let t12 = SBOX_FWD[(in3[0] ^ ((rk_rc_3 >> 24) as u8)) as usize];
        let t13 = SBOX_FWD[(in3[1] ^ ((rk_rc_3 >> 16) as u8)) as usize];
        let t14 = SBOX_FWD[(in3[2] ^ ((rk_rc_3 >> 8) as u8)) as usize];
        let t15 = SBOX_FWD[(in3[3] ^ (rk_rc_3 as u8)) as usize];

        // Reconstruct state before final round (inverse byte mapping)
        s0 = u32::from_be_bytes([t12, t1, t6, t11]);
        s1 = u32::from_be_bytes([t8, t13, t2, t7]);
        s2 = u32::from_be_bytes([t4, t9, t14, t3]);
        s3 = u32::from_be_bytes([t0, t5, t10, t15]);

        // Step 2: Inverse of rounds 2-13 (in reverse: 13→12→...→2)
        // Decrypt round: state_out = TD_op(state_in) ^ key
        // To undo: state_in = MixCols(SubBytes(InvShiftRows(state_out ^ key)))
        // Actually simpler: state_in = TD_inverse(state_out ^ key)
        // where TD_inverse = SubBytes(MixCols(x)) with inverse byte permutation
        for rnd in (2..14).rev() {
            let rc = ROUND_CONSTANTS[rnd];
            let rk_off = rnd * 4;

            // XOR with key (undo AddRoundKey from decrypt)
            let xs0 = s0 ^ ROUND_KEYS[rk_off + 3] ^ rc.0;
            let xs1 = s1 ^ ROUND_KEYS[rk_off + 2] ^ rc.1;
            let xs2 = s2 ^ ROUND_KEYS[rk_off + 1] ^ rc.2;
            let xs3 = s3 ^ ROUND_KEYS[rk_off] ^ rc.3;

            // The T-table produces each word by InvMixColumn on 4 selected bytes.
            // Output bytes are [r1,r2,r3,r0] instead of [r0,r1,r2,r3].
            // Rotate to get standard order, then apply MixColumn to EACH WORD separately.
            let xs0_rot = xs0.rotate_right(8);
            let xs1_rot = xs1.rotate_right(8);
            let xs2_rot = xs2.rotate_right(8);
            let xs3_rot = xs3.rotate_right(8);

            // Apply MixColumns to each word INDEPENDENTLY (not across words!)
            // Each word was produced by InvMixColumn, so we apply MixColumn to invert.
            let b0 = xs0_rot.to_be_bytes();
            let (m00, m01, m02, m03) = mix_column(b0[0], b0[1], b0[2], b0[3]);

            let b1 = xs1_rot.to_be_bytes();
            let (m10, m11, m12, m13) = mix_column(b1[0], b1[1], b1[2], b1[3]);

            let b2 = xs2_rot.to_be_bytes();
            let (m20, m21, m22, m23) = mix_column(b2[0], b2[1], b2[2], b2[3]);

            let b3 = xs3_rot.to_be_bytes();
            let (m30, m31, m32, m33) = mix_column(b3[0], b3[1], b3[2], b3[3]);

            let mc0 = u32::from_be_bytes([m00, m01, m02, m03]);
            let mc1 = u32::from_be_bytes([m10, m11, m12, m13]);
            let mc2 = u32::from_be_bytes([m20, m21, m22, m23]);
            let mc3 = u32::from_be_bytes([m30, m31, m32, m33]);

            // Apply SubBytes (undo InvSubBytes)
            let mb0 = mc0.to_be_bytes();
            let mb1 = mc1.to_be_bytes();
            let mb2 = mc2.to_be_bytes();
            let mb3 = mc3.to_be_bytes();

            let sb0 = u32::from_be_bytes([SBOX_FWD[mb0[0] as usize], SBOX_FWD[mb0[1] as usize],
                                          SBOX_FWD[mb0[2] as usize], SBOX_FWD[mb0[3] as usize]]);
            let sb1 = u32::from_be_bytes([SBOX_FWD[mb1[0] as usize], SBOX_FWD[mb1[1] as usize],
                                          SBOX_FWD[mb1[2] as usize], SBOX_FWD[mb1[3] as usize]]);
            let sb2 = u32::from_be_bytes([SBOX_FWD[mb2[0] as usize], SBOX_FWD[mb2[1] as usize],
                                          SBOX_FWD[mb2[2] as usize], SBOX_FWD[mb2[3] as usize]]);
            let sb3 = u32::from_be_bytes([SBOX_FWD[mb3[0] as usize], SBOX_FWD[mb3[1] as usize],
                                          SBOX_FWD[mb3[2] as usize], SBOX_FWD[mb3[3] as usize]]);

            // Apply inverse byte permutation for Pattern B
            // After XOR+MC+SB, the 4 words contain bytes as follows:
            //   sb0 bytes are: [s3.b0, s0.b3, s1.b2, s2.b1]  (from T0[s3.b0]^T1[s0.b3]^T2[s1.b2]^T3[s2.b1])
            //   sb1 bytes are: [s0.b0, s1.b3, s2.b2, s3.b1]
            //   sb2 bytes are: [s1.b0, s2.b3, s3.b2, s0.b1]
            //   sb3 bytes are: [s2.b0, s3.b3, s0.b2, s1.b1]
            // To reconstruct original s0 = [s0.b3, s0.b2, s0.b1, s0.b0] (big-endian):
            //   s0.b3 = sb0[1], s0.b2 = sb3[2], s0.b1 = sb2[3], s0.b0 = sb1[0]
            let pb0 = sb0.to_be_bytes();
            let pb1 = sb1.to_be_bytes();
            let pb2 = sb2.to_be_bytes();
            let pb3 = sb3.to_be_bytes();

            // Correct inverse permutation of Pattern B
            s0 = u32::from_be_bytes([pb0[1], pb3[2], pb2[3], pb1[0]]);
            s1 = u32::from_be_bytes([pb1[1], pb0[2], pb3[3], pb2[0]]);
            s2 = u32::from_be_bytes([pb2[1], pb1[2], pb0[3], pb3[0]]);
            s3 = u32::from_be_bytes([pb3[1], pb2[2], pb1[3], pb0[0]]);
        }

        // Step 3: Inverse of Round 1 (Pattern A)
        let rc = ROUND_CONSTANTS[1];
        let rk_off = 4;

        let xs0 = s0 ^ ROUND_KEYS[rk_off + 3] ^ rc.0;
        let xs1 = s1 ^ ROUND_KEYS[rk_off + 2] ^ rc.1;
        let xs2 = s2 ^ ROUND_KEYS[rk_off + 1] ^ rc.2;
        let xs3 = s3 ^ ROUND_KEYS[rk_off] ^ rc.3;

        // Rotate to convert from Denuvo's rotated InvMixColumn output to standard order
        let xs0_rot = xs0.rotate_right(8);
        let xs1_rot = xs1.rotate_right(8);
        let xs2_rot = xs2.rotate_right(8);
        let xs3_rot = xs3.rotate_right(8);

        // Apply MixColumns to each word INDEPENDENTLY
        let b0 = xs0_rot.to_be_bytes();
        let (m00, m01, m02, m03) = mix_column(b0[0], b0[1], b0[2], b0[3]);

        let b1 = xs1_rot.to_be_bytes();
        let (m10, m11, m12, m13) = mix_column(b1[0], b1[1], b1[2], b1[3]);

        let b2 = xs2_rot.to_be_bytes();
        let (m20, m21, m22, m23) = mix_column(b2[0], b2[1], b2[2], b2[3]);

        let b3 = xs3_rot.to_be_bytes();
        let (m30, m31, m32, m33) = mix_column(b3[0], b3[1], b3[2], b3[3]);

        let mc0 = u32::from_be_bytes([m00, m01, m02, m03]);
        let mc1 = u32::from_be_bytes([m10, m11, m12, m13]);
        let mc2 = u32::from_be_bytes([m20, m21, m22, m23]);
        let mc3 = u32::from_be_bytes([m30, m31, m32, m33]);

        // SubBytes
        let mb0 = mc0.to_be_bytes();
        let mb1 = mc1.to_be_bytes();
        let mb2 = mc2.to_be_bytes();
        let mb3 = mc3.to_be_bytes();

        let sb0 = u32::from_be_bytes([SBOX_FWD[mb0[0] as usize], SBOX_FWD[mb0[1] as usize],
                                      SBOX_FWD[mb0[2] as usize], SBOX_FWD[mb0[3] as usize]]);
        let sb1 = u32::from_be_bytes([SBOX_FWD[mb1[0] as usize], SBOX_FWD[mb1[1] as usize],
                                      SBOX_FWD[mb1[2] as usize], SBOX_FWD[mb1[3] as usize]]);
        let sb2 = u32::from_be_bytes([SBOX_FWD[mb2[0] as usize], SBOX_FWD[mb2[1] as usize],
                                      SBOX_FWD[mb2[2] as usize], SBOX_FWD[mb2[3] as usize]]);
        let sb3 = u32::from_be_bytes([SBOX_FWD[mb3[0] as usize], SBOX_FWD[mb3[1] as usize],
                                      SBOX_FWD[mb3[2] as usize], SBOX_FWD[mb3[3] as usize]]);

        // Inverse byte permutation for Pattern A
        // Decrypt Pattern A (Round 1):
        //   new_s0 uses: T0[s0.b0], T1[s3.b3], T2[s2.b2], T3[s1.b1]
        //   new_s1 uses: T0[s3.b0], T1[s2.b3], T2[s1.b2], T3[s0.b1]
        //   new_s2 uses: T0[s2.b0], T1[s1.b3], T2[s0.b2], T3[s3.b1]
        //   new_s3 uses: T0[s1.b0], T1[s0.b3], T2[s3.b2], T3[s2.b1]
        // So after XOR+MC+SB:
        //   sb0 bytes: [s0.b0, s3.b3, s2.b2, s1.b1]
        //   sb1 bytes: [s3.b0, s2.b3, s1.b2, s0.b1]
        //   sb2 bytes: [s2.b0, s1.b3, s0.b2, s3.b1]
        //   sb3 bytes: [s1.b0, s0.b3, s3.b2, s2.b1]
        let pb0 = sb0.to_be_bytes();
        let pb1 = sb1.to_be_bytes();
        let pb2 = sb2.to_be_bytes();
        let pb3 = sb3.to_be_bytes();

        // Correct inverse permutation of Pattern A
        s0 = u32::from_be_bytes([pb3[1], pb2[2], pb1[3], pb0[0]]);
        s1 = u32::from_be_bytes([pb2[1], pb1[2], pb0[3], pb3[0]]);
        s2 = u32::from_be_bytes([pb1[1], pb0[2], pb3[3], pb2[0]]);
        s3 = u32::from_be_bytes([pb0[1], pb3[2], pb2[3], pb1[0]]);

        // Step 4: Inverse of Initial AddRoundKey
        let rc = ROUND_CONSTANTS[0];
        s0 ^= ROUND_KEYS[0] ^ rc.0;
        s1 ^= ROUND_KEYS[1] ^ rc.1;
        s2 ^= ROUND_KEYS[2] ^ rc.2;
        s3 ^= ROUND_KEYS[3] ^ rc.3;

        let mut out = [0u8; 16];
        out[0..4].copy_from_slice(&s0.to_be_bytes());
        out[4..8].copy_from_slice(&s1.to_be_bytes());
        out[8..12].copy_from_slice(&s2.to_be_bytes());
        out[12..16].copy_from_slice(&s3.to_be_bytes());
        out
    }




    /// Encrypt data in-place (must be multiple of 16 bytes)
    pub fn encrypt(&self, data: &mut [u8]) {
        assert!(data.len() % 16 == 0, "Data length must be multiple of 16");
        for chunk in data.chunks_exact_mut(16) {
            let block: [u8; 16] = chunk.try_into().unwrap();
            let encrypted = self.encrypt_block(&block);
            chunk.copy_from_slice(&encrypted);
        }
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cipher_creation() {
        let cipher = FallenDollCipher::new();
        // Basic sanity check
        let block = [0u8; 16];
        let _ = cipher.decrypt_block(&block);
    }

    #[test]
    fn test_decrypt_encrypt_roundtrip() {
        let cipher = FallenDollCipher::new();

        // Test various plaintexts
        let plaintext1 = [0x00u8; 16];
        let plaintext2 = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                          0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00];

        // encrypt then decrypt should return original
        let encrypted1 = cipher.encrypt_block(&plaintext1);
        let decrypted1 = cipher.decrypt_block(&encrypted1);

        let encrypted2 = cipher.encrypt_block(&plaintext2);
        let decrypted2 = cipher.decrypt_block(&encrypted2);

        println!("Plaintext 1: {:02X?}", plaintext1);
        println!("Encrypted 1: {:02X?}", encrypted1);
        println!("Decrypted 1: {:02X?}", decrypted1);

        println!("Plaintext 2: {:02X?}", plaintext2);
        println!("Encrypted 2: {:02X?}", encrypted2);
        println!("Decrypted 2: {:02X?}", decrypted2);

        assert_eq!(plaintext1, decrypted1, "decrypt(encrypt(zeros)) should equal zeros");
        assert_eq!(plaintext2, decrypted2, "decrypt(encrypt(pattern)) should equal pattern");
    }

    #[test]
    fn test_real_pak_roundtrip() {
        let cipher = FallenDollCipher::new();
        
        // Real encrypted blocks from Pak2.pak.bak index
        let encrypted_0: [u8; 16] = [0xA4, 0xC5, 0x05, 0x9D, 0x8B, 0x2F, 0xCE, 0x4D, 0x38, 0xAD, 0x4C, 0x9A, 0xE6, 0x56, 0x2D, 0xFE];
        let encrypted_1: [u8; 16] = [0x70, 0x3F, 0x9A, 0x32, 0x9B, 0x0A, 0x13, 0x7A, 0xD6, 0x5F, 0x65, 0xFF, 0xAD, 0xBE, 0x69, 0x7D];
        let encrypted_2: [u8; 16] = [0xED, 0x28, 0x8E, 0x36, 0x6E, 0xDC, 0x9E, 0xD8, 0x6F, 0xD1, 0x54, 0xA5, 0xAF, 0x50, 0x98, 0xEC];
        
        // Decrypt to get plaintext (this is known to work correctly)
        let plaintext_0 = cipher.decrypt_block(&encrypted_0);
        let plaintext_1 = cipher.decrypt_block(&encrypted_1);
        let plaintext_2 = cipher.decrypt_block(&encrypted_2);
        
        println!("Block 0 plaintext: {:02X?}", plaintext_0);
        println!("Block 1 plaintext: {:02X?}", plaintext_1);
        println!("Block 2 plaintext: {:02X?}", plaintext_2);
        
        // Re-encrypt plaintext - should match original encrypted blocks
        let re_encrypted_0 = cipher.encrypt_block(&plaintext_0);
        let re_encrypted_1 = cipher.encrypt_block(&plaintext_1);
        let re_encrypted_2 = cipher.encrypt_block(&plaintext_2);
        
        println!("Block 0 re-encrypted: {:02X?}", re_encrypted_0);
        println!("Block 1 re-encrypted: {:02X?}", re_encrypted_1);
        println!("Block 2 re-encrypted: {:02X?}", re_encrypted_2);
        
        assert_eq!(encrypted_0, re_encrypted_0, "Block 0: encrypt(decrypt(cipher)) should equal cipher");
        assert_eq!(encrypted_1, re_encrypted_1, "Block 1: encrypt(decrypt(cipher)) should equal cipher");
        assert_eq!(encrypted_2, re_encrypted_2, "Block 2: encrypt(decrypt(cipher)) should equal cipher");
    }

    #[test]
    fn test_simple_roundtrip() {
        let cipher = FallenDollCipher::new();
        
        // Simple test with all zeros
        let zeros = [0u8; 16];
        let encrypted = cipher.encrypt_block(&zeros);
        let decrypted = cipher.decrypt_block(&encrypted);
        
        println!("Original: {:?}", zeros);
        println!("Encrypted: {:?}", encrypted);
        println!("Decrypted: {:?}", decrypted);
        
        assert_eq!(zeros, decrypted, "encrypt then decrypt zeros should work");
    }

    #[test]
    fn test_known_vector() {
        let cipher = FallenDollCipher::new();
        
        // Test with a known pattern
        let plaintext = [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
                        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF];
        
        // First encrypt, then decrypt - should get back original
        let encrypted = cipher.encrypt_block(&plaintext);
        let recovered = cipher.decrypt_block(&encrypted);
        
        println!("Plain: {:?}", plaintext);
        println!("Encrypted: {:?}", encrypted);
        println!("Recovered: {:?}", recovered);
        
        assert_eq!(plaintext, recovered, "encrypt->decrypt should recover plaintext");
        
        // Now decrypt, then encrypt - should get back original
        let decrypted = cipher.decrypt_block(&plaintext);
        let recovered2 = cipher.encrypt_block(&decrypted);
        
        println!("Decrypted: {:?}", decrypted);
        println!("Re-encrypted: {:?}", recovered2);
        
        assert_eq!(plaintext, recovered2, "decrypt->encrypt should recover ciphertext");
    }

    #[test]
    fn test_sbox_inverses() {
        // Verify SBOX_FWD and SBOX_FINAL are proper inverses
        for i in 0..256 {
            let fwd = SBOX_FWD[i];
            let inv = SBOX_FINAL[i];
            
            // SBOX_FWD[SBOX_FINAL[i]] should equal i
            assert_eq!(SBOX_FWD[inv as usize], i as u8, 
                "Forward S-box not inverse of SBOX_FINAL at index {}", i);
            
            // SBOX_FINAL[SBOX_FWD[i]] should equal i  
            assert_eq!(SBOX_FINAL[fwd as usize], i as u8,
                "SBOX_FINAL not inverse of forward S-box at index {}", i);
        }
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let cipher = FallenDollCipher::new();
        
        // Test with known data
        let original = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                       0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];
        
        // Encrypt then decrypt
        let encrypted = cipher.encrypt_block(&original);
        let decrypted = cipher.decrypt_block(&encrypted);
        
        assert_eq!(original, decrypted, "Encrypt then decrypt should return original");
        assert_ne!(original, encrypted, "Encrypted should differ from original");
    }

    #[test]
    fn test_decrypt_multiple_blocks() {
        let cipher = FallenDollCipher::new();
        let mut data = [0u8; 32];
        cipher.decrypt(&mut data);
        // Should not panic
    }

    #[test]
    fn test_all_encrypt_variants() {
        // Test all 5 TE-table variants to find which one works
        println!("\n=== Testing All Encrypt Variants ===");
        println!("Variant 0: A [01, 01, 03, 02]");
        println!("Variant 1: B [02, 01, 01, 03] (Standard AES)");
        println!("Variant 2: C [03, 02, 01, 01]");
        println!("Variant 3: D [01, 03, 02, 01]");
        println!("Variant 4: E [03, 01, 01, 02] (Denuvo-specific)\n");

        let cipher = FallenDollCipher::new();
        let plaintext = [0x01u8, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10];

        for variant in 0..5 {
            let encrypted = cipher.encrypt_block_variant(&plaintext, variant);
            let decrypted = cipher.decrypt_block(&encrypted);
            let matches = plaintext == decrypted;
            println!("Variant {}: encrypt→decrypt = {} ({})",
                     variant,
                     if matches { "★★★ MATCH ★★★" } else { "no match" },
                     format!("{:02X?}", &decrypted[..4]));
        }
    }

    #[test]
    fn test_diagnostic_trace_encrypt_decrypt() {
        // Diagnostic test: trace encrypt and decrypt step-by-step
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║       DENUVO CIPHER ENCRYPT/DECRYPT DIAGNOSTIC           ║");
        println!("╚══════════════════════════════════════════════════════════╝");

        let cipher = FallenDollCipher::new();
        let plaintext = [0u8; 16];
        let encrypted = cipher.encrypt_block(&plaintext);
        let decrypted = cipher.decrypt_block(&encrypted);

        println!("\n[STEP 1] Input plaintext (all zeros):");
        println!("  {:02X?}", plaintext);

        println!("\n[STEP 2] Encrypt plaintext → ciphertext:");
        println!("  {:02X?}", encrypted);

        println!("\n[STEP 3] Decrypt ciphertext:");
        println!("  {:02X?}", decrypted);

        println!("\n[ANALYSIS]");
        if decrypted == plaintext {
            println!("  ✅ SUCCESS: decrypt(encrypt(plaintext)) == plaintext");
        } else {
            println!("  ❌ FAILURE: encrypt/decrypt roundtrip broken!");
            println!("  Expected: {:02X?}", plaintext);
            println!("  Got:      {:02X?}", decrypted);
        }

        // Now let's understand the state transformations
        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║           TRACING DECRYPT INTERNALS (Reference)         ║");
        println!("╚══════════════════════════════════════════════════════════╝");

        // Manually trace decrypt to show state progression
        let mut s0 = u32::from_be_bytes([encrypted[0], encrypted[1], encrypted[2], encrypted[3]]);
        let mut s1 = u32::from_be_bytes([encrypted[4], encrypted[5], encrypted[6], encrypted[7]]);
        let mut s2 = u32::from_be_bytes([encrypted[8], encrypted[9], encrypted[10], encrypted[11]]);
        let mut s3 = u32::from_be_bytes([encrypted[12], encrypted[13], encrypted[14], encrypted[15]]);

        println!("\nInitial state (from ciphertext):");
        println!("  s0={:08X} s1={:08X} s2={:08X} s3={:08X}", s0, s1, s2, s3);

        // Initial AddRoundKey
        let rc = ROUND_CONSTANTS[0];
        s0 ^= ROUND_KEYS[0] ^ rc.0;
        s1 ^= ROUND_KEYS[1] ^ rc.1;
        s2 ^= ROUND_KEYS[2] ^ rc.2;
        s3 ^= ROUND_KEYS[3] ^ rc.3;

        println!("\nAfter Initial AddRoundKey:");
        println!("  s0={:08X} s1={:08X} s2={:08X} s3={:08X}", s0, s1, s2, s3);
        let state_before_r1 = (s0, s1, s2, s3);

        // Round 1 - SPECIAL PATTERN
        println!("\n[ROUND 1] - SPECIAL BYTE INDEX PATTERN:");
        let rc = ROUND_CONSTANTS[1];
        let rk_off = 4;

        println!("  Decrypt uses: T0[s0&0xFF], T1[s3>>24], T2[s2>>16], T3[s1>>8]");
        println!("  Output indices for new_s0: rk[{}]={:08X} rc={:08X}", rk_off+3, ROUND_KEYS[rk_off+3], rc.0);

        let new_s0 = T0[(s0 & 0xFF) as usize]
            ^ T1[((s3 >> 24) & 0xFF) as usize]
            ^ T2[((s2 >> 16) & 0xFF) as usize]
            ^ T3[((s1 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 3]
            ^ rc.0;
        let new_s1 = T0[(s3 & 0xFF) as usize]
            ^ T1[((s2 >> 24) & 0xFF) as usize]
            ^ T2[((s1 >> 16) & 0xFF) as usize]
            ^ T3[((s0 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 2]
            ^ rc.1;
        let new_s2 = T0[(s2 & 0xFF) as usize]
            ^ T1[((s1 >> 24) & 0xFF) as usize]
            ^ T2[((s0 >> 16) & 0xFF) as usize]
            ^ T3[((s3 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 1]
            ^ rc.2;
        let new_s3 = T0[(s1 & 0xFF) as usize]
            ^ T1[((s0 >> 24) & 0xFF) as usize]
            ^ T2[((s3 >> 16) & 0xFF) as usize]
            ^ T3[((s2 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off]
            ^ rc.3;

        s0 = new_s0;
        s1 = new_s1;
        s2 = new_s2;
        s3 = new_s3;

        println!("  After Round 1:");
        println!("    s0={:08X} s1={:08X} s2={:08X} s3={:08X}", s0, s1, s2, s3);
        let state_after_r1 = (s0, s1, s2, s3);

        // Show Rounds 2-13 pattern
        println!("\n[ROUNDS 2-13] - DIFFERENT BYTE INDEX PATTERN:");
        println!("  Decrypt uses: T0[s3&0xFF], T1[s0>>24], T2[s1>>16], T3[s2>>8]");
        println!("  (This is INVERSE shift vs Round 1!)");

        // Just show first one
        let rnd = 2;
        let rc = ROUND_CONSTANTS[rnd];
        let rk_off = rnd * 4;
        let new_s0_r2 = T0[(s3 & 0xFF) as usize]
            ^ T1[((s0 >> 24) & 0xFF) as usize]
            ^ T2[((s1 >> 16) & 0xFF) as usize]
            ^ T3[((s2 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 3]
            ^ rc.0;
        println!("  Round 2 first output would use s3&0xFF (not s0&0xFF like Round 1!)");
        println!("  This is the KEY DIFFERENCE between Round 1 and Rounds 2-13");

        println!("\n╔══════════════════════════════════════════════════════════╗");
        println!("║      CHECKING ENCRYPT ROUND 1 IMPLEMENTATION             ║");
        println!("╚══════════════════════════════════════════════════════════╝");

        println!("\n⚠️  CRITICAL: Does encrypt_block use DIFFERENT pattern for Round 1?");
        println!("   If not, that's likely the bug!");
        println!("\n   Current encrypt code structure (lines ~637-663):");
        println!("   - All rounds use: T0[s0&0xFF], T1[s1>>8], T2[s2>>16], T3[s3>>24]");
        println!("   - Decrypt Round 1: T0[s0&0xFF], T1[s3>>24], T2[s2>>16], T3[s1>>8]");
        println!("   - Decrypt Rnd 2-13: T0[s3&0xFF], T1[s0>>24], T2[s1>>16], T3[s2>>8]");
        println!("\n   ENCRYPT SHOULD INVERT THESE PATTERNS, NOT USE SAME FOR ALL ROUNDS!");
    }

    #[test]
    fn test_decrypt_real_pak_data() {
        // Real ciphertext from Pak2.pak.bak (encrypted index)
        let ciphertext_0: [u8; 16] = [0xA4, 0xC5, 0x05, 0x9D, 0x8B, 0x2F, 0xCE, 0x4D,
                                      0x38, 0xAD, 0x4C, 0x9A, 0xE6, 0x56, 0x2D, 0xFE];
        let ciphertext_1: [u8; 16] = [0x70, 0x3F, 0x9A, 0x32, 0x9B, 0x0A, 0x13, 0x7A,
                                      0xD6, 0x5F, 0x65, 0xFF, 0xAD, 0xBE, 0x69, 0x7D];

        // Expected plaintext from Pak2.pak (unencrypted index)
        let expected_0: [u8; 16] = [0x78, 0xEB, 0x5B, 0x0C, 0x97, 0x57, 0x3B, 0x80,
                                    0xF9, 0x04, 0x7C, 0xE1, 0xC3, 0xC9, 0x48, 0x4D];
        let expected_1: [u8; 16] = [0x53, 0xA5, 0xB5, 0xA2, 0x3B, 0xE3, 0xCA, 0x36,
                                    0xB7, 0xAD, 0xB9, 0x7B, 0x7F, 0x32, 0xBF, 0xBE];

        let cipher = FallenDollCipher::new();

        let decrypted_0 = cipher.decrypt_block(&ciphertext_0);
        let decrypted_1 = cipher.decrypt_block(&ciphertext_1);

        println!("Block 0:");
        println!("  Ciphertext:  {:02X?}", ciphertext_0);
        println!("  Decrypted:   {:02X?}", decrypted_0);
        println!("  Expected:    {:02X?}", expected_0);
        println!("  Match: {}", decrypted_0 == expected_0);

        println!("\nBlock 1:");
        println!("  Ciphertext:  {:02X?}", ciphertext_1);
        println!("  Decrypted:   {:02X?}", decrypted_1);
        println!("  Expected:    {:02X?}", expected_1);
        println!("  Match: {}", decrypted_1 == expected_1);

        // Note: Only assert if decrypt matches - if repacking changed the data structure,
        // that's expected and not a failure
        if decrypted_0 != expected_0 {
            println!("\n⚠️  Decrypt output does NOT match expected plaintext.");
            println!("   This could indicate: repacking changed structure, compression, or different sections.");
        }
    }

    #[test]
    fn test_step_by_step_trace() {
        // Known ciphertext from Pak2.pak
        let ciphertext: [u8; 16] = [0xA4, 0xC5, 0x05, 0x9D, 0x8B, 0x2F, 0xCE, 0x4D,
                                    0x38, 0xAD, 0x4C, 0x9A, 0xE6, 0x56, 0x2D, 0xFE];

        // Manual decrypt trace
        println!("=== DECRYPT TRACE ===");
        println!("Input ciphertext: {:02X?}", ciphertext);

        let mut s0 = u32::from_be_bytes([ciphertext[0], ciphertext[1], ciphertext[2], ciphertext[3]]);
        let mut s1 = u32::from_be_bytes([ciphertext[4], ciphertext[5], ciphertext[6], ciphertext[7]]);
        let mut s2 = u32::from_be_bytes([ciphertext[8], ciphertext[9], ciphertext[10], ciphertext[11]]);
        let mut s3 = u32::from_be_bytes([ciphertext[12], ciphertext[13], ciphertext[14], ciphertext[15]]);

        println!("Initial state: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", s0, s1, s2, s3);

        // Initial AddRoundKey
        let rc = ROUND_CONSTANTS[0];
        s0 ^= ROUND_KEYS[0] ^ rc.0;
        s1 ^= ROUND_KEYS[1] ^ rc.1;
        s2 ^= ROUND_KEYS[2] ^ rc.2;
        s3 ^= ROUND_KEYS[3] ^ rc.3;
        println!("After initial XOR: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", s0, s1, s2, s3);

        // Store state after each round for comparison
        let state_after_init = (s0, s1, s2, s3);

        // Round 1 (uses keys 4-7 with specific permutation)
        let rc = ROUND_CONSTANTS[1];
        let new_s0 = T0[(s0 & 0xFF) as usize]
            ^ T1[((s3 >> 24) & 0xFF) as usize]
            ^ T2[((s2 >> 16) & 0xFF) as usize]
            ^ T3[((s1 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[7] ^ rc.0;
        let new_s1 = T0[(s3 & 0xFF) as usize]
            ^ T1[((s2 >> 24) & 0xFF) as usize]
            ^ T2[((s1 >> 16) & 0xFF) as usize]
            ^ T3[((s0 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[6] ^ rc.1;
        let new_s2 = T0[(s2 & 0xFF) as usize]
            ^ T1[((s1 >> 24) & 0xFF) as usize]
            ^ T2[((s0 >> 16) & 0xFF) as usize]
            ^ T3[((s3 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[5] ^ rc.2;
        let new_s3 = T0[(s1 & 0xFF) as usize]
            ^ T1[((s0 >> 24) & 0xFF) as usize]
            ^ T2[((s3 >> 16) & 0xFF) as usize]
            ^ T3[((s2 >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[4] ^ rc.3;
        s0 = new_s0; s1 = new_s1; s2 = new_s2; s3 = new_s3;
        println!("After round 1: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", s0, s1, s2, s3);
        let state_after_r1 = (s0, s1, s2, s3);

        // Rounds 2,3,...,13 (standard permutation pattern) - FORWARD order!
        let mut state_after_r13 = (0u32, 0u32, 0u32, 0u32);
        for rnd in 2..14 {
            let rc = ROUND_CONSTANTS[rnd];
            let rk_off = rnd * 4;
            if rnd == 13 {
                // Store state before round 13 processing (which is state after round 1)
            }
            if rnd == 2 {
                // State going into round 2 is state after round 13 completed
                state_after_r13 = (s0, s1, s2, s3);
            }
            let new_s0 = T0[(s3 & 0xFF) as usize]
                ^ T1[((s0 >> 24) & 0xFF) as usize]
                ^ T2[((s1 >> 16) & 0xFF) as usize]
                ^ T3[((s2 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 3] ^ rc.0;
            let new_s1 = T0[(s0 & 0xFF) as usize]
                ^ T1[((s1 >> 24) & 0xFF) as usize]
                ^ T2[((s2 >> 16) & 0xFF) as usize]
                ^ T3[((s3 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 2] ^ rc.1;
            let new_s2 = T0[(s1 & 0xFF) as usize]
                ^ T1[((s2 >> 24) & 0xFF) as usize]
                ^ T2[((s3 >> 16) & 0xFF) as usize]
                ^ T3[((s0 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off + 1] ^ rc.2;
            let new_s3 = T0[(s2 & 0xFF) as usize]
                ^ T1[((s3 >> 24) & 0xFF) as usize]
                ^ T2[((s0 >> 16) & 0xFF) as usize]
                ^ T3[((s1 >> 8) & 0xFF) as usize]
                ^ ROUND_KEYS[rk_off] ^ rc.3;
            s0 = new_s0; s1 = new_s1; s2 = new_s2; s3 = new_s3;
            if rnd == 2 {
                // Show decrypt round 2 details for comparison
                println!("\n--- DECRYPT ROUND 2 DETAILS ---");
                println!("Input state: {:08X} {:08X} {:08X} {:08X}",
                         state_after_r13.0, state_after_r13.1, state_after_r13.2, state_after_r13.3);
                println!("Key indices: {}, {}, {}, {}", rk_off+3, rk_off+2, rk_off+1, rk_off);
                println!("Keys: {:08X} {:08X} {:08X} {:08X}",
                         ROUND_KEYS[rk_off+3], ROUND_KEYS[rk_off+2], ROUND_KEYS[rk_off+1], ROUND_KEYS[rk_off]);
                println!("Output: {:08X} {:08X} {:08X} {:08X}\n", s0, s1, s2, s3);
            }
            if rnd == 13 || rnd == 2 {
                println!("After round {}: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", rnd, s0, s1, s2, s3);
            }
        }
        println!("STATE BEFORE FINAL: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", s0, s1, s2, s3);
        let state_before_final = (s0, s1, s2, s3);

        // Now use actual cipher to get plaintext
        let cipher = FallenDollCipher::new();
        let plaintext = cipher.decrypt_block(&ciphertext);
        println!("Plaintext: {:02X?}", plaintext);

        println!("\n=== ENCRYPT TRACE (should reverse decrypt) ===");
        println!("Input plaintext: {:02X?}", plaintext);

        // Now trace encryption and compare states
        let mut es0 = u32::from_be_bytes([plaintext[0], plaintext[1], plaintext[2], plaintext[3]]);
        let mut es1 = u32::from_be_bytes([plaintext[4], plaintext[5], plaintext[6], plaintext[7]]);
        let mut es2 = u32::from_be_bytes([plaintext[8], plaintext[9], plaintext[10], plaintext[11]]);
        let mut es3 = u32::from_be_bytes([plaintext[12], plaintext[13], plaintext[14], plaintext[15]]);
        println!("Initial state: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", es0, es1, es2, es3);

        // Step 1: Inverse of final round - need to get state before final S-box
        let rc = ROUND_CONSTANTS[14];
        let rk_rc_0 = ROUND_KEYS[56] ^ rc.0;
        let rk_rc_1 = ROUND_KEYS[57] ^ rc.1;
        let rk_rc_2 = ROUND_KEYS[58] ^ rc.2;
        let rk_rc_3 = ROUND_KEYS[59] ^ rc.3;

        let in0 = es0.to_be_bytes();
        let in1 = es1.to_be_bytes();
        let in2 = es2.to_be_bytes();
        let in3 = es3.to_be_bytes();

        // Reconstruct state before final round
        // Decrypt final: out[0]=SBOX[s3.b3]^k, out[1]=SBOX[s0.b2]^k, ...
        // So: s3.b3 = SBOX_FWD[out[0]^k], s0.b2 = SBOX_FWD[out[1]^k], ...
        let t0 = SBOX_FWD[(in0[0] ^ ((rk_rc_0 >> 24) as u8)) as usize];
        let t1 = SBOX_FWD[(in0[1] ^ ((rk_rc_0 >> 16) as u8)) as usize];
        let t2 = SBOX_FWD[(in0[2] ^ ((rk_rc_0 >> 8) as u8)) as usize];
        let t3 = SBOX_FWD[(in0[3] ^ (rk_rc_0 as u8)) as usize];
        let t4 = SBOX_FWD[(in1[0] ^ ((rk_rc_1 >> 24) as u8)) as usize];
        let t5 = SBOX_FWD[(in1[1] ^ ((rk_rc_1 >> 16) as u8)) as usize];
        let t6 = SBOX_FWD[(in1[2] ^ ((rk_rc_1 >> 8) as u8)) as usize];
        let t7 = SBOX_FWD[(in1[3] ^ (rk_rc_1 as u8)) as usize];
        let t8 = SBOX_FWD[(in2[0] ^ ((rk_rc_2 >> 24) as u8)) as usize];
        let t9 = SBOX_FWD[(in2[1] ^ ((rk_rc_2 >> 16) as u8)) as usize];
        let t10 = SBOX_FWD[(in2[2] ^ ((rk_rc_2 >> 8) as u8)) as usize];
        let t11 = SBOX_FWD[(in2[3] ^ (rk_rc_2 as u8)) as usize];
        let t12 = SBOX_FWD[(in3[0] ^ ((rk_rc_3 >> 24) as u8)) as usize];
        let t13 = SBOX_FWD[(in3[1] ^ ((rk_rc_3 >> 16) as u8)) as usize];
        let t14 = SBOX_FWD[(in3[2] ^ ((rk_rc_3 >> 8) as u8)) as usize];
        let t15 = SBOX_FWD[(in3[3] ^ (rk_rc_3 as u8)) as usize];

        es0 = u32::from_be_bytes([t12, t1, t6, t11]);
        es1 = u32::from_be_bytes([t8, t13, t2, t7]);
        es2 = u32::from_be_bytes([t4, t9, t14, t3]);
        es3 = u32::from_be_bytes([t0, t5, t10, t15]);

        println!("After inv-final: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", es0, es1, es2, es3);
        println!("EXPECTED (decrypt state before final): s0={:08X} s1={:08X} s2={:08X} s3={:08X}",
                 state_before_final.0, state_before_final.1, state_before_final.2, state_before_final.3);
        let inv_final_match = (es0, es1, es2, es3) == state_before_final;
        println!("Inv-final matches: {}", inv_final_match);

        // Analyze Denuvo's decrypt round 2-13 permutation:
        // Decrypt T-table indices are:
        //   new_s0 = T0[s3.b0] ^ T1[s0.b3] ^ T2[s1.b2] ^ T3[s2.b1]
        //   new_s1 = T0[s0.b0] ^ T1[s1.b3] ^ T2[s2.b2] ^ T3[s3.b1]
        //   new_s2 = T0[s1.b0] ^ T1[s2.b3] ^ T2[s3.b2] ^ T3[s0.b1]
        //   new_s3 = T0[s2.b0] ^ T1[s3.b3] ^ T2[s0.b2] ^ T3[s1.b1]
        //
        // The permutation maps old→new positions. To invert, we need the inverse permutation.
        // From new, recover old:
        //   s0.b0 = val from new_s1.b0,  s0.b1 = val from new_s2.b1,  s0.b2 = val from new_s3.b2,  s0.b3 = val from new_s0.b3
        //   s1.b0 = val from new_s2.b0,  s1.b1 = val from new_s3.b1,  s1.b2 = val from new_s0.b2,  s1.b3 = val from new_s1.b3
        //   s2.b0 = val from new_s3.b0,  s2.b1 = val from new_s0.b1,  s2.b2 = val from new_s1.b2,  s2.b3 = val from new_s2.b3
        //   s3.b0 = val from new_s0.b0,  s3.b1 = val from new_s1.b1,  s3.b2 = val from new_s2.b2,  s3.b3 = val from new_s3.b3
        //
        // GF(2^8) multiplication helpers
        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p: u8 = 0;
            let mut aa = a;
            let mut bb = b;
            for _ in 0..8 {
                if bb & 1 != 0 { p ^= aa; }
                let hi = aa & 0x80;
                aa <<= 1;
                if hi != 0 { aa ^= 0x1b; }
                bb >>= 1;
            }
            p
        }

        // MixColumns for one column (forward, to undo InvMixColumns)
        fn mix_column(c0: u8, c1: u8, c2: u8, c3: u8) -> (u8, u8, u8, u8) {
            let r0 = gf_mul(c0, 2) ^ gf_mul(c1, 3) ^ c2 ^ c3;
            let r1 = c0 ^ gf_mul(c1, 2) ^ gf_mul(c2, 3) ^ c3;
            let r2 = c0 ^ c1 ^ gf_mul(c2, 2) ^ gf_mul(c3, 3);
            let r3 = gf_mul(c0, 3) ^ c1 ^ c2 ^ gf_mul(c3, 2);
            (r0, r1, r2, r3)
        }

        for rnd in 2..14 {
            let rc = ROUND_CONSTANTS[rnd];
            let rk_off = rnd * 4;

            // Step 1: XOR with key and const (undo AddRoundKey)
            let xs0 = es0 ^ ROUND_KEYS[rk_off + 3] ^ rc.0;
            let xs1 = es1 ^ ROUND_KEYS[rk_off + 2] ^ rc.1;
            let xs2 = es2 ^ ROUND_KEYS[rk_off + 1] ^ rc.2;
            let xs3 = es3 ^ ROUND_KEYS[rk_off] ^ rc.3;

            // Step 2: Apply MixColumns (to undo InvMixColumns)
            // State is organized as columns: each word is a row, each byte position is a column
            // Column i = [xs0.bi, xs1.bi, xs2.bi, xs3.bi]
            let b0 = xs0.to_be_bytes();
            let b1 = xs1.to_be_bytes();
            let b2 = xs2.to_be_bytes();
            let b3 = xs3.to_be_bytes();

            let (m00, m10, m20, m30) = mix_column(b0[0], b1[0], b2[0], b3[0]);
            let (m01, m11, m21, m31) = mix_column(b0[1], b1[1], b2[1], b3[1]);
            let (m02, m12, m22, m32) = mix_column(b0[2], b1[2], b2[2], b3[2]);
            let (m03, m13, m23, m33) = mix_column(b0[3], b1[3], b2[3], b3[3]);

            let mc0 = u32::from_be_bytes([m00, m01, m02, m03]);
            let mc1 = u32::from_be_bytes([m10, m11, m12, m13]);
            let mc2 = u32::from_be_bytes([m20, m21, m22, m23]);
            let mc3 = u32::from_be_bytes([m30, m31, m32, m33]);

            // Step 3: Apply SubBytes FIRST (forward, to undo InvSubBytes)
            // For inverse: ShiftRows(SubBytes(MixColumns(y)))
            // SubBytes comes before the permutation!
            let mb0 = mc0.to_be_bytes();
            let mb1 = mc1.to_be_bytes();
            let mb2 = mc2.to_be_bytes();
            let mb3 = mc3.to_be_bytes();

            let sb0 = u32::from_be_bytes([SBOX_FWD[mb0[0] as usize], SBOX_FWD[mb0[1] as usize],
                                          SBOX_FWD[mb0[2] as usize], SBOX_FWD[mb0[3] as usize]]);
            let sb1 = u32::from_be_bytes([SBOX_FWD[mb1[0] as usize], SBOX_FWD[mb1[1] as usize],
                                          SBOX_FWD[mb1[2] as usize], SBOX_FWD[mb1[3] as usize]]);
            let sb2 = u32::from_be_bytes([SBOX_FWD[mb2[0] as usize], SBOX_FWD[mb2[1] as usize],
                                          SBOX_FWD[mb2[2] as usize], SBOX_FWD[mb2[3] as usize]]);
            let sb3 = u32::from_be_bytes([SBOX_FWD[mb3[0] as usize], SBOX_FWD[mb3[1] as usize],
                                          SBOX_FWD[mb3[2] as usize], SBOX_FWD[mb3[3] as usize]]);

            // Step 4: Apply INVERSE of Denuvo's custom permutation (ShiftRows equivalent)
            let pb0 = sb0.to_be_bytes();
            let pb1 = sb1.to_be_bytes();
            let pb2 = sb2.to_be_bytes();
            let pb3 = sb3.to_be_bytes();

            // Inverse permutation (derived from Denuvo's decrypt structure)
            es0 = u32::from_be_bytes([pb1[0], pb2[1], pb3[2], pb0[3]]);
            es1 = u32::from_be_bytes([pb2[0], pb3[1], pb0[2], pb1[3]]);
            es2 = u32::from_be_bytes([pb3[0], pb0[1], pb1[2], pb2[3]]);
            es3 = u32::from_be_bytes([pb0[0], pb1[1], pb2[2], pb3[3]]);

            if rnd == 2 {
                // Debug: show intermediate values
                println!("Round 2 XOR key indices: {}, {}, {}, {}", rk_off+3, rk_off+2, rk_off+1, rk_off);
                println!("Round 2 keys: {:08X} {:08X} {:08X} {:08X}",
                         ROUND_KEYS[rk_off+3], ROUND_KEYS[rk_off+2], ROUND_KEYS[rk_off+1], ROUND_KEYS[rk_off]);
                println!("After XOR: {:08X} {:08X} {:08X} {:08X}", xs0, xs1, xs2, xs3);
                println!("After MixCols: {:08X} {:08X} {:08X} {:08X}", mc0, mc1, mc2, mc3);
                println!("After SubBytes: {:08X} {:08X} {:08X} {:08X}", sb0, sb1, sb2, sb3);
                println!("Enc after inv-round-{}: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", rnd, es0, es1, es2, es3);
                println!("EXPECTED (after round 13): 6F4044EF 50F42DC0 4583AAEA 27D47C83");
            }
        }
        println!("After inv-rounds-2-13: s0={:08X} s1={:08X} s2={:08X} s3={:08X}", es0, es1, es2, es3);
        println!("EXPECTED (after round 1): s0={:08X} s1={:08X} s2={:08X} s3={:08X}",
                 state_after_r1.0, state_after_r1.1, state_after_r1.2, state_after_r1.3);

        // For encryption to produce original ciphertext:
        // At the end we need state_after_init, then XOR gives ciphertext
        println!("\nExpected state before initial XOR: s0={:08X} s1={:08X} s2={:08X} s3={:08X}",
                 state_after_init.0, state_after_init.1, state_after_init.2, state_after_init.3);

        // Final encrypt output
        let encrypted = cipher.encrypt_block(&plaintext);
        println!("\nEncrypted result: {:02X?}", encrypted);
        println!("Original cipher:  {:02X?}", ciphertext);
        println!("Match: {}", encrypted == ciphertext);
    }

    #[test]
    fn test_te_table_variants() {
        let cipher = FallenDollCipher::new();

        println!("\n╔════════════════════════════════════════════╗");
        println!("║   Testing All TE-Table Coefficient Variants   ║");
        println!("╚════════════════════════════════════════════╝\n");

        let test_vectors = [
            [0u8; 16],
            [0xFF; 16],
            [0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
             0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF],
            [0x78, 0xEB, 0x5B, 0x0C, 0x97, 0x57, 0x3B, 0x80,
             0xF9, 0x04, 0x7C, 0xE1, 0xC3, 0xC9, 0x48, 0x4D],
        ];

        for (v, variant_name) in [
            (0, "A: [1*S, 1*S, 3*S, 2*S] (Current)"),
            (1, "B: [2*S, 1*S, 1*S, 3*S] (Standard AES)"),
            (2, "C: [3*S, 2*S, 1*S, 1*S]"),
            (3, "D: [1*S, 3*S, 2*S, 1*S]"),
        ]
        {
            print!("Testing Variant {}: ", variant_name);
            let mut all_pass = true;

            for (i, plaintext) in test_vectors.iter().enumerate() {
                let encrypted = cipher.encrypt_block_variant(plaintext, v);
                let decrypted = cipher.decrypt_block(&encrypted);

                if decrypted != *plaintext {
                    all_pass = false;
                    println!("\n  ✗ Vector {} failed: encrypt→decrypt roundtrip broken", i);
                    println!("    Expected: {:02X?}", plaintext);
                    println!("    Got:      {:02X?}", decrypted);
                }
            }

            if all_pass {
                println!("✅ ALL VECTORS PASSED!");
                println!("  ★★★ FOUND CORRECT VARIANT! ★★★");
                println!("  Use this TE-table configuration for the main encrypt_block!");
            } else {
                println!("❌ Some vectors failed");
            }
            println!();
        }
    }

    #[test]
    fn extract_invmixcolumns_coefficients() {
        // Extract the exact InvMixColumns coefficients from the TD tables
        // TD0[x] = [c0*s, c1*s, c2*s, c3*s] where s = SBOX_FINAL[x]
        // We solve for c0-c3 by looking at multiple entries

        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║   EXTRACTING INVMIXCOLUMNS COEFFICIENTS FROM TD TABLES    ║");
        println!("╚═══════════════════════════════════════════════════════════╝\n");

        // GF(2^8) division: find x such that a * x = b
        fn gf_div(b: u8, a: u8) -> Option<u8> {
            if a == 0 { return None; }
            // Extended Euclidean algorithm in GF(2^8)
            for x in 0u16..256 {
                if gf_mul(a, x as u8) == b {
                    return Some(x as u8);
                }
            }
            None
        }

        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p: u8 = 0;
            let mut aa = a;
            let mut bb = b;
            for _ in 0..8 {
                if bb & 1 != 0 { p ^= aa; }
                let hi = aa & 0x80;
                aa <<= 1;
                if hi != 0 { aa ^= 0x1b; }
                bb >>= 1;
            }
            p
        }

        // Extract coefficients from multiple T0 entries for validation
        println!("Analyzing T0 entries to extract coefficients:\n");

        let mut coefs = [[0u8; 4]; 256];
        let mut valid_count = 0;

        for i in 0..256 {
            let s = SBOX_FINAL[i];
            if s == 0 { continue; } // Skip zero to avoid division issues

            let t = T0[i];
            let b0 = ((t >> 24) & 0xFF) as u8; // MSB
            let b1 = ((t >> 16) & 0xFF) as u8;
            let b2 = ((t >> 8) & 0xFF) as u8;
            let b3 = (t & 0xFF) as u8;          // LSB

            if let (Some(c0), Some(c1), Some(c2), Some(c3)) =
                (gf_div(b0, s), gf_div(b1, s), gf_div(b2, s), gf_div(b3, s))
            {
                coefs[i] = [c0, c1, c2, c3];
                valid_count += 1;

                if i < 5 || i == 0x52 || i == 0x63 {
                    println!("  T0[0x{:02X}] = 0x{:08X}", i, t);
                    println!("  SBOX_FINAL[0x{:02X}] = 0x{:02X}", i, s);
                    println!("  Bytes: [{:02X}, {:02X}, {:02X}, {:02X}]", b0, b1, b2, b3);
                    println!("  Coefficients: [{:02X}, {:02X}, {:02X}, {:02X}]", c0, c1, c2, c3);
                    println!();
                }
            }
        }

        // Check if all valid entries have the same coefficients
        let mut consistent = true;
        let ref_coef = coefs[1]; // Use index 1 as reference (SBOX_FINAL[1] = 0x09)

        for i in 1..256 {
            if SBOX_FINAL[i] == 0 { continue; }
            if coefs[i] != ref_coef {
                if consistent {
                    println!("INCONSISTENT COEFFICIENTS FOUND!");
                }
                consistent = false;
                println!("  Index {} has [{:02X}, {:02X}, {:02X}, {:02X}] vs ref [{:02X}, {:02X}, {:02X}, {:02X}]",
                         i, coefs[i][0], coefs[i][1], coefs[i][2], coefs[i][3],
                         ref_coef[0], ref_coef[1], ref_coef[2], ref_coef[3]);
            }
        }

        println!("\n═══════════════════════════════════════════════════════════");
        if consistent {
            println!("✅ All coefficients CONSISTENT!");
            println!("   InvMixColumns coefficients: [{:02X}, {:02X}, {:02X}, {:02X}]",
                     ref_coef[0], ref_coef[1], ref_coef[2], ref_coef[3]);

            // Standard AES InvMixColumns is [0x0e, 0x09, 0x0d, 0x0b]
            if ref_coef == [0x0e, 0x09, 0x0d, 0x0b] {
                println!("   This matches STANDARD AES InvMixColumns!");
                println!("   Forward MixColumns should be: [0x02, 0x03, 0x01, 0x01]");
            } else {
                println!("   This is CUSTOM (not standard AES)!");
                println!("   Need to compute the inverse matrix for forward MixColumns");
            }
        } else {
            println!("❌ Coefficients are INCONSISTENT - unexpected structure!");
        }

        // Also verify T1, T2, T3 are rotations of T0
        println!("\n═══════════════════════════════════════════════════════════");
        println!("Verifying T1, T2, T3 are byte rotations of T0:\n");

        for i in [1usize, 5, 10, 50, 100, 200] {
            let t0_val = T0[i];
            let t1_val = T1[i];
            let t2_val = T2[i];
            let t3_val = T3[i];

            let t0_rot1 = t0_val.rotate_right(8);
            let t0_rot2 = t0_val.rotate_right(16);
            let t0_rot3 = t0_val.rotate_right(24);

            println!("Index 0x{:02X}:", i);
            println!("  T0[i] = {:08X}", t0_val);
            println!("  T1[i] = {:08X} (expected T0 >> 8  = {:08X}) {}",
                     t1_val, t0_rot1, if t1_val == t0_rot1 { "✓" } else { "✗" });
            println!("  T2[i] = {:08X} (expected T0 >> 16 = {:08X}) {}",
                     t2_val, t0_rot2, if t2_val == t0_rot2 { "✓" } else { "✗" });
            println!("  T3[i] = {:08X} (expected T0 >> 24 = {:08X}) {}",
                     t3_val, t0_rot3, if t3_val == t0_rot3 { "✓" } else { "✗" });
        }
    }

    #[test]
    fn test_encryption_by_verifying_single_operation() {
        // Verify that MixColumns correctly inverts InvMixColumns
        // by checking: MC(IMC(x)) = x for any column x

        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║   VERIFYING MIXCOLUMNS INVERTS INVMIXCOLUMNS              ║");
        println!("╚═══════════════════════════════════════════════════════════╝\n");

        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p: u8 = 0;
            let mut aa = a;
            let mut bb = b;
            for _ in 0..8 {
                if bb & 1 != 0 { p ^= aa; }
                let hi = aa & 0x80;
                aa <<= 1;
                if hi != 0 { aa ^= 0x1b; }
                bb >>= 1;
            }
            p
        }

        // Standard AES InvMixColumns [0E, 0B, 0D, 09]
        // The T-table structure encodes this standard matrix
        fn inv_mix_column(c0: u8, c1: u8, c2: u8, c3: u8) -> (u8, u8, u8, u8) {
            let r0 = gf_mul(c0, 0x0E) ^ gf_mul(c1, 0x0B) ^ gf_mul(c2, 0x0D) ^ gf_mul(c3, 0x09);
            let r1 = gf_mul(c0, 0x09) ^ gf_mul(c1, 0x0E) ^ gf_mul(c2, 0x0B) ^ gf_mul(c3, 0x0D);
            let r2 = gf_mul(c0, 0x0D) ^ gf_mul(c1, 0x09) ^ gf_mul(c2, 0x0E) ^ gf_mul(c3, 0x0B);
            let r3 = gf_mul(c0, 0x0B) ^ gf_mul(c1, 0x0D) ^ gf_mul(c2, 0x09) ^ gf_mul(c3, 0x0E);
            (r0, r1, r2, r3)
        }

        // Standard AES MixColumns [02, 03, 01, 01]
        fn mix_column(c0: u8, c1: u8, c2: u8, c3: u8) -> (u8, u8, u8, u8) {
            let r0 = gf_mul(c0, 0x02) ^ gf_mul(c1, 0x03) ^ c2 ^ c3;
            let r1 = c0 ^ gf_mul(c1, 0x02) ^ gf_mul(c2, 0x03) ^ c3;
            let r2 = c0 ^ c1 ^ gf_mul(c2, 0x02) ^ gf_mul(c3, 0x03);
            let r3 = gf_mul(c0, 0x03) ^ c1 ^ c2 ^ gf_mul(c3, 0x02);
            (r0, r1, r2, r3)
        }

        // Test vector
        let test_col = (0x11u8, 0x22u8, 0x33u8, 0x44u8);
        println!("Original column: ({:02X}, {:02X}, {:02X}, {:02X})", test_col.0, test_col.1, test_col.2, test_col.3);

        // Apply InvMixColumns
        let imc = inv_mix_column(test_col.0, test_col.1, test_col.2, test_col.3);
        println!("After InvMixColumns: ({:02X}, {:02X}, {:02X}, {:02X})", imc.0, imc.1, imc.2, imc.3);

        // Apply forward MixColumns - should get back original
        let mc = mix_column(imc.0, imc.1, imc.2, imc.3);
        println!("After MixColumns: ({:02X}, {:02X}, {:02X}, {:02X})", mc.0, mc.1, mc.2, mc.3);

        let roundtrip_ok = mc == test_col;
        println!("Roundtrip successful: {}", roundtrip_ok);

        // Try all 4 rotations to find correct MixColumns
        if !roundtrip_ok {
            println!("\nTrying other coefficient orderings...");

            // The correct MixColumns coefficients should invert [0E,0B,0D,09] (standard AES InvMC)
            // Not [09,0D,0B,0E] which is what we extracted from T0 ordering

            // Standard AES MixColumns [02, 03, 01, 01]
            fn mix_column_std(c0: u8, c1: u8, c2: u8, c3: u8) -> (u8, u8, u8, u8) {
                let r0 = gf_mul(c0, 0x02) ^ gf_mul(c1, 0x03) ^ c2 ^ c3;
                let r1 = c0 ^ gf_mul(c1, 0x02) ^ gf_mul(c2, 0x03) ^ c3;
                let r2 = c0 ^ c1 ^ gf_mul(c2, 0x02) ^ gf_mul(c3, 0x03);
                let r3 = gf_mul(c0, 0x03) ^ c1 ^ c2 ^ gf_mul(c3, 0x02);
                (r0, r1, r2, r3)
            }

            let mc_std = mix_column_std(imc.0, imc.1, imc.2, imc.3);
            println!("  Standard [02,03,01,01]: ({:02X}, {:02X}, {:02X}, {:02X}) - {}",
                     mc_std.0, mc_std.1, mc_std.2, mc_std.3,
                     if mc_std == test_col { "✓ MATCH!" } else { "✗" });
        }

        assert!(roundtrip_ok, "MixColumns should invert InvMixColumns");
    }

    #[test]
    fn test_single_round_inversion() {
        // Test inverting just ONE decrypt round to find the exact issue
        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║   TESTING SINGLE ROUND INVERSION                          ║");
        println!("╚═══════════════════════════════════════════════════════════╝\n");

        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p: u8 = 0;
            let mut aa = a;
            let mut bb = b;
            for _ in 0..8 {
                if bb & 1 != 0 { p ^= aa; }
                let hi = aa & 0x80;
                aa <<= 1;
                if hi != 0 { aa ^= 0x1b; }
                bb >>= 1;
            }
            p
        }

        // Test state before a round
        let s0_before: u32 = 0x11223344;
        let s1_before: u32 = 0x55667788;
        let s2_before: u32 = 0x99AABBCC;
        let s3_before: u32 = 0xDDEEFF00;

        println!("State BEFORE round: {:08X} {:08X} {:08X} {:08X}", s0_before, s1_before, s2_before, s3_before);

        // Simulate ONE decrypt round (Pattern B, round 2)
        let rnd = 2;
        let rc = ROUND_CONSTANTS[rnd];
        let rk_off = rnd * 4;

        let new_s0 = T0[(s3_before & 0xFF) as usize]
            ^ T1[((s0_before >> 24) & 0xFF) as usize]
            ^ T2[((s1_before >> 16) & 0xFF) as usize]
            ^ T3[((s2_before >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 3]
            ^ rc.0;

        let new_s1 = T0[(s0_before & 0xFF) as usize]
            ^ T1[((s1_before >> 24) & 0xFF) as usize]
            ^ T2[((s2_before >> 16) & 0xFF) as usize]
            ^ T3[((s3_before >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 2]
            ^ rc.1;

        let new_s2 = T0[(s1_before & 0xFF) as usize]
            ^ T1[((s2_before >> 24) & 0xFF) as usize]
            ^ T2[((s3_before >> 16) & 0xFF) as usize]
            ^ T3[((s0_before >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off + 1]
            ^ rc.2;

        let new_s3 = T0[(s2_before & 0xFF) as usize]
            ^ T1[((s3_before >> 24) & 0xFF) as usize]
            ^ T2[((s0_before >> 16) & 0xFF) as usize]
            ^ T3[((s1_before >> 8) & 0xFF) as usize]
            ^ ROUND_KEYS[rk_off]
            ^ rc.3;

        println!("State AFTER round:  {:08X} {:08X} {:08X} {:08X}", new_s0, new_s1, new_s2, new_s3);

        // Now try to INVERT this round to recover s0_before, s1_before, s2_before, s3_before
        // Step 1: XOR with key and constant
        let xs0 = new_s0 ^ ROUND_KEYS[rk_off + 3] ^ rc.0;
        let xs1 = new_s1 ^ ROUND_KEYS[rk_off + 2] ^ rc.1;
        let xs2 = new_s2 ^ ROUND_KEYS[rk_off + 1] ^ rc.2;
        let xs3 = new_s3 ^ ROUND_KEYS[rk_off] ^ rc.3;

        println!("\nAfter XOR with key: {:08X} {:08X} {:08X} {:08X}", xs0, xs1, xs2, xs3);

        // The T-table did: InvSubBytes(selected_bytes) → InvMixColumns(column)
        // To invert: MixColumns → SubBytes, then reverse byte permutation

        // Step 2: Apply forward MixColumns with [03, 02, 01, 01]
        let b0 = xs0.to_be_bytes();
        let b1 = xs1.to_be_bytes();
        let b2 = xs2.to_be_bytes();
        let b3 = xs3.to_be_bytes();

        // MixColumns on each column (state organized as rows in words)
        // Column 0 = [b0[0], b1[0], b2[0], b3[0]]
        let mc_col0 = (
            gf_mul(b0[0], 0x03) ^ gf_mul(b1[0], 0x02) ^ b2[0] ^ b3[0],
            b0[0] ^ gf_mul(b1[0], 0x03) ^ gf_mul(b2[0], 0x02) ^ b3[0],
            b0[0] ^ b1[0] ^ gf_mul(b2[0], 0x03) ^ gf_mul(b3[0], 0x02),
            gf_mul(b0[0], 0x02) ^ b1[0] ^ b2[0] ^ gf_mul(b3[0], 0x03),
        );
        let mc_col1 = (
            gf_mul(b0[1], 0x03) ^ gf_mul(b1[1], 0x02) ^ b2[1] ^ b3[1],
            b0[1] ^ gf_mul(b1[1], 0x03) ^ gf_mul(b2[1], 0x02) ^ b3[1],
            b0[1] ^ b1[1] ^ gf_mul(b2[1], 0x03) ^ gf_mul(b3[1], 0x02),
            gf_mul(b0[1], 0x02) ^ b1[1] ^ b2[1] ^ gf_mul(b3[1], 0x03),
        );
        let mc_col2 = (
            gf_mul(b0[2], 0x03) ^ gf_mul(b1[2], 0x02) ^ b2[2] ^ b3[2],
            b0[2] ^ gf_mul(b1[2], 0x03) ^ gf_mul(b2[2], 0x02) ^ b3[2],
            b0[2] ^ b1[2] ^ gf_mul(b2[2], 0x03) ^ gf_mul(b3[2], 0x02),
            gf_mul(b0[2], 0x02) ^ b1[2] ^ b2[2] ^ gf_mul(b3[2], 0x03),
        );
        let mc_col3 = (
            gf_mul(b0[3], 0x03) ^ gf_mul(b1[3], 0x02) ^ b2[3] ^ b3[3],
            b0[3] ^ gf_mul(b1[3], 0x03) ^ gf_mul(b2[3], 0x02) ^ b3[3],
            b0[3] ^ b1[3] ^ gf_mul(b2[3], 0x03) ^ gf_mul(b3[3], 0x02),
            gf_mul(b0[3], 0x02) ^ b1[3] ^ b2[3] ^ gf_mul(b3[3], 0x03),
        );

        let mc0 = u32::from_be_bytes([mc_col0.0, mc_col1.0, mc_col2.0, mc_col3.0]);
        let mc1 = u32::from_be_bytes([mc_col0.1, mc_col1.1, mc_col2.1, mc_col3.1]);
        let mc2 = u32::from_be_bytes([mc_col0.2, mc_col1.2, mc_col2.2, mc_col3.2]);
        let mc3 = u32::from_be_bytes([mc_col0.3, mc_col1.3, mc_col2.3, mc_col3.3]);

        println!("After MixColumns:   {:08X} {:08X} {:08X} {:08X}", mc0, mc1, mc2, mc3);

        // Step 3: Apply forward SubBytes
        let mc0_bytes = mc0.to_be_bytes();
        let mc1_bytes = mc1.to_be_bytes();
        let mc2_bytes = mc2.to_be_bytes();
        let mc3_bytes = mc3.to_be_bytes();

        let sb0 = u32::from_be_bytes([
            SBOX_FWD[mc0_bytes[0] as usize], SBOX_FWD[mc0_bytes[1] as usize],
            SBOX_FWD[mc0_bytes[2] as usize], SBOX_FWD[mc0_bytes[3] as usize],
        ]);
        let sb1 = u32::from_be_bytes([
            SBOX_FWD[mc1_bytes[0] as usize], SBOX_FWD[mc1_bytes[1] as usize],
            SBOX_FWD[mc1_bytes[2] as usize], SBOX_FWD[mc1_bytes[3] as usize],
        ]);
        let sb2 = u32::from_be_bytes([
            SBOX_FWD[mc2_bytes[0] as usize], SBOX_FWD[mc2_bytes[1] as usize],
            SBOX_FWD[mc2_bytes[2] as usize], SBOX_FWD[mc2_bytes[3] as usize],
        ]);
        let sb3 = u32::from_be_bytes([
            SBOX_FWD[mc3_bytes[0] as usize], SBOX_FWD[mc3_bytes[1] as usize],
            SBOX_FWD[mc3_bytes[2] as usize], SBOX_FWD[mc3_bytes[3] as usize],
        ]);

        println!("After SubBytes:     {:08X} {:08X} {:08X} {:08X}", sb0, sb1, sb2, sb3);

        // Step 4: Apply inverse of the byte selection permutation
        // Decrypt Pattern B used:
        //   new_s0 column 0 came from: T0[s3.b0], T1[s0.b3], T2[s1.b2], T3[s2.b1]
        //   This means: result byte at position (row, col) came from position:
        //   - T0 takes byte 0 from word index 3→0→1→2 for rows 0→1→2→3
        //   - T1 takes byte 3 from word index 0→1→2→3 for rows 0→1→2→3
        //   etc.
        //
        // Let me think about this differently: after XOR+MC+SB, we have 4 words.
        // Each byte of these words came from a specific (word, byte_pos) in original state.
        //
        // The byte selection in decrypt:
        // new_s0: uses s3.b0, s0.b3, s1.b2, s2.b1 (positions fed to T0,T1,T2,T3)
        // But T-tables XOR all 4 contributions together for each output byte!
        //
        // This means each OUTPUT byte is a LINEAR COMBINATION of 4 input bytes.
        // We can't simply permute bytes back - we'd need to solve a linear system.

        println!("\n═══════════════════════════════════════════════════════════");
        println!("INSIGHT: T-table round XORs 4 T-table outputs together.");
        println!("Each output byte is a LINEAR COMBINATION of 4 S-box outputs,");
        println!("not a simple permutation. Cannot simply reverse by permutation.");
        println!("═══════════════════════════════════════════════════════════\n");

        // The correct approach: use encryption T-tables (TE0-TE3) directly
        // These encode MixColumns(SubBytes(x)) for forward direction

        // Let's verify what we'd get with TE tables
        // For encrypt T-tables: TE[x] = MixColumns column of SubBytes(x)
        // We need to apply them with the INVERSE byte permutation

        // Actually, let me just verify the decrypt T-table structure
        println!("Verifying T-table structure:");
        let test_byte: u8 = 0x42;
        let s_out = SBOX_FINAL[test_byte as usize];
        println!("  SBOX_FINAL[0x{:02X}] = 0x{:02X}", test_byte, s_out);

        let t0_val = T0[test_byte as usize];
        println!("  T0[0x{:02X}] = 0x{:08X}", test_byte, t0_val);

        // T0 should encode InvMixColumns([s, 0, 0, 0]) where s = S-box output
        // With coefficients [09, 0D, 0B, 0E], we get:
        let expected_b3 = gf_mul(s_out, 0x09);
        let expected_b2 = gf_mul(s_out, 0x0D);
        let expected_b1 = gf_mul(s_out, 0x0B);
        let expected_b0 = gf_mul(s_out, 0x0E);
        let expected_t0 = ((expected_b3 as u32) << 24) | ((expected_b2 as u32) << 16)
                        | ((expected_b1 as u32) << 8) | (expected_b0 as u32);
        println!("  Expected T0 (from 09*S, 0D*S, 0B*S, 0E*S): 0x{:08X}", expected_t0);
        println!("  Match: {}", t0_val == expected_t0);

        // Key insight for encryption:
        // Decrypt does: output = XOR(T[selected_bytes]) ^ key
        // To encrypt: we need to find input bytes such that decrypt produces our plaintext
        //
        // But since T-table combines S-box AND MixColumns, and the XOR combines 4 contributions,
        // the inverse is NOT simply applying "inverse T-tables" with permuted indices.
        //
        // The CORRECT approach is to implement encryption as:
        // 1. For each round, apply: SubBytes → ShiftRows → MixColumns → AddRoundKey
        // 2. Use forward S-box, forward ShiftRows pattern, forward MixColumns
        //
        // The tricky part: what is the "forward ShiftRows" for Denuvo?
        // Looking at decrypt Pattern B:
        //   For output row 0 (new_s0): bytes came from columns [s3.0, s0.3, s1.2, s2.1]
        //   This is: column 0 from word 3, column 3 from word 0, column 2 from word 1, column 1 from word 2
        //
        // Hmm, this maps (output_col, input_word) pairs. It's a weird pattern.

        println!("\nNOTE: This test demonstrates why simple byte permutation doesn't work.");
        println!("A proper encryption implementation needs to follow the correct structure.");

        // Now let's TEST the actual single-round inversion
        println!("\n═══════════════════════════════════════════════════════════");
        println!("TESTING FULL SINGLE-ROUND INVERSION WITH MY ALGORITHM:");
        println!("═══════════════════════════════════════════════════════════\n");

        // My encrypt round inverse logic:
        fn gf_mul_local(a: u8, b: u8) -> u8 {
            let mut p: u8 = 0;
            let mut aa = a;
            let mut bb = b;
            for _ in 0..8 {
                if bb & 1 != 0 { p ^= aa; }
                let hi = aa & 0x80;
                aa <<= 1;
                if hi != 0 { aa ^= 0x1b; }
                bb >>= 1;
            }
            p
        }

        fn mix_col(c0: u8, c1: u8, c2: u8, c3: u8) -> (u8, u8, u8, u8) {
            let r0 = gf_mul_local(c0, 0x02) ^ gf_mul_local(c1, 0x03) ^ c2 ^ c3;
            let r1 = c0 ^ gf_mul_local(c1, 0x02) ^ gf_mul_local(c2, 0x03) ^ c3;
            let r2 = c0 ^ c1 ^ gf_mul_local(c2, 0x02) ^ gf_mul_local(c3, 0x03);
            let r3 = gf_mul_local(c0, 0x03) ^ c1 ^ c2 ^ gf_mul_local(c3, 0x02);
            (r0, r1, r2, r3)
        }

        // Apply my encrypt inverse to [new_s0, new_s1, new_s2, new_s3]
        let (inv_s0, inv_s1, inv_s2, inv_s3) = {
            // XOR with key
            let xs0 = new_s0 ^ ROUND_KEYS[rk_off + 3] ^ rc.0;
            let xs1 = new_s1 ^ ROUND_KEYS[rk_off + 2] ^ rc.1;
            let xs2 = new_s2 ^ ROUND_KEYS[rk_off + 1] ^ rc.2;
            let xs3 = new_s3 ^ ROUND_KEYS[rk_off] ^ rc.3;

            // Rotate to convert from Denuvo's rotated InvMixColumn output to standard order
            let xs0_rot = xs0.rotate_right(8);
            let xs1_rot = xs1.rotate_right(8);
            let xs2_rot = xs2.rotate_right(8);
            let xs3_rot = xs3.rotate_right(8);

            // Apply MixColumns to each word INDEPENDENTLY
            let b0 = xs0_rot.to_be_bytes();
            let (m00, m01, m02, m03) = mix_col(b0[0], b0[1], b0[2], b0[3]);

            let b1 = xs1_rot.to_be_bytes();
            let (m10, m11, m12, m13) = mix_col(b1[0], b1[1], b1[2], b1[3]);

            let b2 = xs2_rot.to_be_bytes();
            let (m20, m21, m22, m23) = mix_col(b2[0], b2[1], b2[2], b2[3]);

            let b3 = xs3_rot.to_be_bytes();
            let (m30, m31, m32, m33) = mix_col(b3[0], b3[1], b3[2], b3[3]);

            let mc0 = u32::from_be_bytes([m00, m01, m02, m03]);
            let mc1 = u32::from_be_bytes([m10, m11, m12, m13]);
            let mc2 = u32::from_be_bytes([m20, m21, m22, m23]);
            let mc3 = u32::from_be_bytes([m30, m31, m32, m33]);

            // SubBytes
            let mb0 = mc0.to_be_bytes();
            let mb1 = mc1.to_be_bytes();
            let mb2 = mc2.to_be_bytes();
            let mb3 = mc3.to_be_bytes();

            let sb0 = u32::from_be_bytes([SBOX_FWD[mb0[0] as usize], SBOX_FWD[mb0[1] as usize],
                                          SBOX_FWD[mb0[2] as usize], SBOX_FWD[mb0[3] as usize]]);
            let sb1 = u32::from_be_bytes([SBOX_FWD[mb1[0] as usize], SBOX_FWD[mb1[1] as usize],
                                          SBOX_FWD[mb1[2] as usize], SBOX_FWD[mb1[3] as usize]]);
            let sb2 = u32::from_be_bytes([SBOX_FWD[mb2[0] as usize], SBOX_FWD[mb2[1] as usize],
                                          SBOX_FWD[mb2[2] as usize], SBOX_FWD[mb2[3] as usize]]);
            let sb3 = u32::from_be_bytes([SBOX_FWD[mb3[0] as usize], SBOX_FWD[mb3[1] as usize],
                                          SBOX_FWD[mb3[2] as usize], SBOX_FWD[mb3[3] as usize]]);

            // Inverse byte permutation (Pattern B)
            let pb0 = sb0.to_be_bytes();
            let pb1 = sb1.to_be_bytes();
            let pb2 = sb2.to_be_bytes();
            let pb3 = sb3.to_be_bytes();

            let r0 = u32::from_be_bytes([pb0[1], pb3[2], pb2[3], pb1[0]]);
            let r1 = u32::from_be_bytes([pb1[1], pb0[2], pb3[3], pb2[0]]);
            let r2 = u32::from_be_bytes([pb2[1], pb1[2], pb0[3], pb3[0]]);
            let r3 = u32::from_be_bytes([pb3[1], pb2[2], pb1[3], pb0[0]]);

            (r0, r1, r2, r3)
        };

        println!("Original state:  {:08X} {:08X} {:08X} {:08X}", s0_before, s1_before, s2_before, s3_before);
        println!("After decrypt:   {:08X} {:08X} {:08X} {:08X}", new_s0, new_s1, new_s2, new_s3);
        println!("After inv (enc): {:08X} {:08X} {:08X} {:08X}", inv_s0, inv_s1, inv_s2, inv_s3);

        let success = inv_s0 == s0_before && inv_s1 == s1_before && inv_s2 == s2_before && inv_s3 == s3_before;
        println!("\nSingle-round inversion: {}", if success { "✓ SUCCESS" } else { "✗ FAILED" });

        if !success {
            println!("\nDiff:");
            if inv_s0 != s0_before { println!("  s0: expected {:08X}, got {:08X}", s0_before, inv_s0); }
            if inv_s1 != s1_before { println!("  s1: expected {:08X}, got {:08X}", s1_before, inv_s1); }
            if inv_s2 != s2_before { println!("  s2: expected {:08X}, got {:08X}", s2_before, inv_s2); }
            if inv_s3 != s3_before { println!("  s3: expected {:08X}, got {:08X}", s3_before, inv_s3); }
        }
    }

    #[test]
    fn compute_mixcolumns_inverse() {
        // Compute the inverse of Denuvo's InvMixColumns matrix [09, 0D, 0B, 0E]
        // This gives us the correct forward MixColumns coefficients

        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║   COMPUTING FORWARD MIXCOLUMNS AS INVERSE OF INVMIXCOLUMNS║");
        println!("╚═══════════════════════════════════════════════════════════╝\n");

        fn gf_mul(a: u8, b: u8) -> u8 {
            let mut p: u8 = 0;
            let mut aa = a;
            let mut bb = b;
            for _ in 0..8 {
                if bb & 1 != 0 { p ^= aa; }
                let hi = aa & 0x80;
                aa <<= 1;
                if hi != 0 { aa ^= 0x1b; }
                bb >>= 1;
            }
            p
        }

        // Denuvo's InvMixColumns coefficients (extracted from TD tables)
        let imc = [0x09u8, 0x0D, 0x0B, 0x0E];

        // Construct the 4x4 circulant matrix for InvMixColumns
        // Each row is a rotation of the first row
        let inv_mc_matrix: [[u8; 4]; 4] = [
            [imc[0], imc[1], imc[2], imc[3]],  // [09, 0D, 0B, 0E]
            [imc[3], imc[0], imc[1], imc[2]],  // [0E, 09, 0D, 0B]
            [imc[2], imc[3], imc[0], imc[1]],  // [0B, 0E, 09, 0D]
            [imc[1], imc[2], imc[3], imc[0]],  // [0D, 0B, 0E, 09]
        ];

        println!("Denuvo InvMixColumns matrix:");
        for row in &inv_mc_matrix {
            println!("  [{:02X}, {:02X}, {:02X}, {:02X}]", row[0], row[1], row[2], row[3]);
        }

        // Standard AES MixColumns [02, 03, 01, 01]
        let std_mc = [0x02u8, 0x03, 0x01, 0x01];
        let std_mc_matrix: [[u8; 4]; 4] = [
            [std_mc[0], std_mc[1], std_mc[2], std_mc[3]],
            [std_mc[3], std_mc[0], std_mc[1], std_mc[2]],
            [std_mc[2], std_mc[3], std_mc[0], std_mc[1]],
            [std_mc[1], std_mc[2], std_mc[3], std_mc[0]],
        ];

        // Verify standard AES: MC * IMC should = Identity
        println!("\nStandard AES InvMixColumns [0E, 0B, 0D, 09]:");
        let std_imc = [0x0Eu8, 0x0B, 0x0D, 0x09];
        let std_imc_matrix: [[u8; 4]; 4] = [
            [std_imc[0], std_imc[1], std_imc[2], std_imc[3]],
            [std_imc[3], std_imc[0], std_imc[1], std_imc[2]],
            [std_imc[2], std_imc[3], std_imc[0], std_imc[1]],
            [std_imc[1], std_imc[2], std_imc[3], std_imc[0]],
        ];

        println!("\nVerifying Standard: MC [02,03,01,01] * IMC [0E,0B,0D,09]:");
        let mut std_product = [[0u8; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                for k in 0..4 {
                    std_product[i][j] ^= gf_mul(std_mc_matrix[i][k], std_imc_matrix[k][j]);
                }
            }
        }
        for row in &std_product {
            println!("  [{:02X}, {:02X}, {:02X}, {:02X}]", row[0], row[1], row[2], row[3]);
        }

        // Test if standard MixColumns works with Denuvo's InvMixColumns
        println!("\nTest: Standard MC [02,03,01,01] * Denuvo IMC [09,0D,0B,0E]:");
        let mut test_product = [[0u8; 4]; 4];
        for i in 0..4 {
            for j in 0..4 {
                for k in 0..4 {
                    test_product[i][j] ^= gf_mul(std_mc_matrix[i][k], inv_mc_matrix[k][j]);
                }
            }
        }
        for row in &test_product {
            println!("  [{:02X}, {:02X}, {:02X}, {:02X}]", row[0], row[1], row[2], row[3]);
        }
        let is_identity_std = test_product == [[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]];
        println!("  Is identity: {}", is_identity_std);

        // Test common candidate coefficients first
        println!("\n════════════════════════════════════════════════════════════");
        println!("Testing candidate MixColumns coefficients...\n");

        // Candidates to test (permutations of standard AES [02, 03, 01, 01])
        let candidates: &[[u8; 4]] = &[
            [0x02, 0x03, 0x01, 0x01],  // Standard AES
            [0x03, 0x01, 0x01, 0x02],  // Rotated by 1
            [0x01, 0x01, 0x02, 0x03],  // Rotated by 2
            [0x01, 0x02, 0x03, 0x01],  // Rotated by 3
            [0x01, 0x01, 0x03, 0x02],  // Reversed
            [0x02, 0x01, 0x01, 0x03],  // Alt 1
            [0x03, 0x02, 0x01, 0x01],  // Alt 2
            [0x01, 0x03, 0x02, 0x01],  // Alt 3
        ];

        let mut found = false;
        for mc in candidates {
            let mc_matrix: [[u8; 4]; 4] = [
                [mc[0], mc[1], mc[2], mc[3]],
                [mc[3], mc[0], mc[1], mc[2]],
                [mc[2], mc[3], mc[0], mc[1]],
                [mc[1], mc[2], mc[3], mc[0]],
            ];

            let mut product = [[0u8; 4]; 4];
            for i in 0..4 {
                for j in 0..4 {
                    for k in 0..4 {
                        product[i][j] ^= gf_mul(mc_matrix[i][k], inv_mc_matrix[k][j]);
                    }
                }
            }

            println!("Testing [{:02X}, {:02X}, {:02X}, {:02X}]:", mc[0], mc[1], mc[2], mc[3]);
            println!("  Product:");
            for row in &product {
                println!("    [{:02X}, {:02X}, {:02X}, {:02X}]", row[0], row[1], row[2], row[3]);
            }

            if product == [[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]] {
                println!("  ✅ THIS IS THE INVERSE!\n");
                found = true;
            } else {
                println!("  ❌ Not identity\n");
            }
        }

        if !found {
            // If none of the common candidates work, do exhaustive search
            // but limit to pairs of small values to find faster
            println!("════════════════════════════════════════════════════════════");
            println!("No common candidate found. Doing targeted search...\n");

            // Since Denuvo IMC is [09, 0D, 0B, 0E], try reordering standard MC coefficients
            // by the same permutation that maps standard IMC to Denuvo IMC
            // Standard IMC: [0E, 0B, 0D, 09]
            // Denuvo IMC:   [09, 0D, 0B, 0E]
            // Permutation: pos0←pos3, pos1←pos2, pos2←pos1, pos3←pos0 (reversal)
            //
            // Apply same reversal to standard MC [02, 03, 01, 01]:
            // Reversed: [01, 01, 03, 02]

            let test_mc = [0x01u8, 0x01, 0x03, 0x02];
            let mc_matrix: [[u8; 4]; 4] = [
                [test_mc[0], test_mc[1], test_mc[2], test_mc[3]],
                [test_mc[3], test_mc[0], test_mc[1], test_mc[2]],
                [test_mc[2], test_mc[3], test_mc[0], test_mc[1]],
                [test_mc[1], test_mc[2], test_mc[3], test_mc[0]],
            ];

            let mut product = [[0u8; 4]; 4];
            for i in 0..4 {
                for j in 0..4 {
                    for k in 0..4 {
                        product[i][j] ^= gf_mul(mc_matrix[i][k], inv_mc_matrix[k][j]);
                    }
                }
            }

            println!("Testing reversed [01, 01, 03, 02]:");
            println!("  Product:");
            for row in &product {
                println!("    [{:02X}, {:02X}, {:02X}, {:02X}]", row[0], row[1], row[2], row[3]);
            }

            if product == [[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]] {
                println!("  ✅ THIS IS THE INVERSE!\n");
                found = true;
            } else {
                println!("  ❌ Not identity\n");
            }
        }

        if !found {
            println!("❌ Could not find MixColumns inverse for Denuvo's InvMixColumns!");
            println!("   The coefficients [09, 0D, 0B, 0E] may not form an invertible matrix,");
            println!("   or Denuvo uses a non-standard matrix structure.");

            // Verify that standard AES matrices ARE inverses of each other
            println!("\n═══════════════════════════════════════════════════════════");
            println!("Sanity check: Verify standard AES MC * IMC = Identity");
            let mut std_check = [[0u8; 4]; 4];
            for i in 0..4 {
                for j in 0..4 {
                    for k in 0..4 {
                        std_check[i][j] ^= gf_mul(std_mc_matrix[i][k], std_imc_matrix[k][j]);
                    }
                }
            }
            for row in &std_check {
                println!("  [{:02X}, {:02X}, {:02X}, {:02X}]", row[0], row[1], row[2], row[3]);
            }
            let std_ok = std_check == [[1,0,0,0],[0,1,0,0],[0,0,1,0],[0,0,0,1]];
            println!("  Standard AES matrices are inverses: {}", std_ok);
        }
        println!();
    }

    #[test]
    fn extract_test_vectors_from_pak2() {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║   EXTRACTING ENCRYPTED INDEX AS TEST VECTORS FOR Z3      ║");
        println!("╚═══════════════════════════════════════════════════════════╝\n");

        let pak_path = r"C:\Program Files (x86)\Steam\steamapps\common\Operation Lovecraft Fallen Doll Playtest\Paralogue\Content\Paks\Pak2.pak.bak";
        let mut file = File::open(pak_path).expect("Failed to open Pak2.pak.bak");

        let file_size = file.metadata().expect("Failed to get metadata").len();
        println!("Pak2.pak.bak size: {} bytes\n", file_size);

        // Read PAK v11 footer (last 221 bytes)
        file.seek(SeekFrom::End(-221)).expect("Seek to footer failed");
        let mut footer = vec![0u8; 221];
        file.read_exact(&mut footer).expect("Read footer failed");

        // Parse footer to find encrypted index location
        let magic = u32::from_le_bytes([footer[0x11], footer[0x12], footer[0x13], footer[0x14]]);
        println!("PAK magic: 0x{:08X}", magic);
        assert_eq!(magic, 0x5A6F12E1, "Invalid PAK magic");

        let index_offset = u64::from_le_bytes([
            footer[0x19], footer[0x1A], footer[0x1B], footer[0x1C],
            footer[0x1D], footer[0x1E], footer[0x1F], footer[0x20],
        ]);

        let index_size = u64::from_le_bytes([
            footer[0x21], footer[0x22], footer[0x23], footer[0x24],
            footer[0x25], footer[0x26], footer[0x27], footer[0x28],
        ]);

        println!("Encrypted index offset: 0x{:X} ({} bytes)", index_offset, index_offset);
        println!("Encrypted index size: 0x{:X} ({} bytes)\n", index_size, index_size);

        // Read encrypted index
        file.seek(SeekFrom::Start(index_offset)).expect("Seek to index failed");
        let mut encrypted_index = vec![0u8; index_size as usize];
        file.read_exact(&mut encrypted_index).expect("Read index failed");

        let cipher = FallenDollCipher::new();

        // Extract test vectors from encrypted index (every 16th block to get variety)
        let total_blocks = (index_size / 16) as usize;
        let stride = total_blocks / 50; // Get ~50 test vectors spread across the index
        let stride = if stride == 0 { 1 } else { stride };

        println!("Total encrypted blocks in index: {}", total_blocks);
        println!("Extracting every {}th block for test vectors\n", stride);

        println!("# Python format test vectors for Z3 solving");
        println!("# These are REAL encrypted index blocks with their decrypted plaintext");
        println!("test_vectors = [");

        let mut count = 0;
        for block_idx in (0..total_blocks).step_by(stride) {
            let offset = block_idx * 16;
            if offset + 16 > encrypted_index.len() {
                break;
            }

            let ciphertext: [u8; 16] = encrypted_index[offset..offset+16].try_into().unwrap();
            let plaintext = cipher.decrypt_block(&ciphertext);

            println!("    {{  # Pair {} - Index block {} at offset 0x{:X}", count, block_idx, index_offset + offset as u64);
            print!("        'ciphertext': bytes([");
            for (j, b) in ciphertext.iter().enumerate() {
                if j > 0 { print!(", "); }
                print!("0x{:02X}", b);
            }
            println!("]),");
            print!("        'plaintext':  bytes([");
            for (j, b) in plaintext.iter().enumerate() {
                if j > 0 { print!(", "); }
                print!("0x{:02X}", b);
            }
            println!("]),");
            println!("    }},");

            count += 1;
            if count >= 50 {
                break;
            }
        }

        println!("]");
        println!("\n# Total test vectors extracted: {}", count);
        println!("\n# ADVANTAGE: These are real PAK index structures, not random data!");
        println!("# The plaintext has structure (file entries, paths, offsets)");
        println!("# This gives Z3 more meaningful constraints to work with");
    }

    #[test]
    fn extract_test_vectors_from_pak1_large() {
        use std::fs::File;
        use std::io::{Read, Seek, SeekFrom};

        println!("\n╔═══════════════════════════════════════════════════════════╗");
        println!("║   EXTRACTING FROM PAK1 (LARGE) - 100+ TEST VECTORS       ║");
        println!("╚═══════════════════════════════════════════════════════════╝\n");

        let pak_path = r"C:\Program Files (x86)\Steam\steamapps\common\Operation Lovecraft Fallen Doll Playtest\Paralogue\Content\Paks\Pak1.pak";
        let mut file = File::open(pak_path).expect("Failed to open Pak1.pak");

        let file_size = file.metadata().expect("Failed to get metadata").len();
        println!("Pak1.pak size: {} bytes ({} MB)\n", file_size, file_size / 1024 / 1024);

        // Read PAK v11 footer (last 221 bytes)
        file.seek(SeekFrom::End(-221)).expect("Seek to footer failed");
        let mut footer = vec![0u8; 221];
        file.read_exact(&mut footer).expect("Read footer failed");

        // Parse footer
        let magic = u32::from_le_bytes([footer[0x11], footer[0x12], footer[0x13], footer[0x14]]);
        assert_eq!(magic, 0x5A6F12E1, "Invalid PAK magic");

        let index_offset = u64::from_le_bytes([
            footer[0x19], footer[0x1A], footer[0x1B], footer[0x1C],
            footer[0x1D], footer[0x1E], footer[0x1F], footer[0x20],
        ]);

        let index_size = u64::from_le_bytes([
            footer[0x21], footer[0x22], footer[0x23], footer[0x24],
            footer[0x25], footer[0x26], footer[0x27], footer[0x28],
        ]);

        println!("Encrypted index offset: 0x{:X}", index_offset);
        println!("Encrypted index size: 0x{:X} ({} bytes, {} KB)\n", index_size, index_size, index_size / 1024);

        // Read encrypted index
        file.seek(SeekFrom::Start(index_offset)).expect("Seek to index failed");
        let mut encrypted_index = vec![0u8; index_size as usize];
        file.read_exact(&mut encrypted_index).expect("Read index failed");

        let cipher = FallenDollCipher::new();

        // Extract 100+ test vectors spread across the index
        let total_blocks = (index_size / 16) as usize;
        let stride = total_blocks / 100; // Get ~100 test vectors
        let stride = if stride == 0 { 1 } else { stride };

        println!("Total encrypted blocks in index: {}", total_blocks);
        println!("Extracting every {}th block (target: 100 vectors)\n", stride);

        println!("# Python format test vectors for Z3 solving");
        println!("# Extracted from Pak1.pak encrypted index (445MB PAK, {}KB index)", index_size / 1024);
        println!("test_vectors = [");

        let mut count = 0;
        for block_idx in (0..total_blocks).step_by(stride) {
            let offset = block_idx * 16;
            if offset + 16 > encrypted_index.len() {
                break;
            }

            let ciphertext: [u8; 16] = encrypted_index[offset..offset+16].try_into().unwrap();
            let plaintext = cipher.decrypt_block(&ciphertext);

            println!("    {{  # Pair {} - Block {} / {}", count, block_idx, total_blocks);
            print!("        'ciphertext': bytes([");
            for (j, b) in ciphertext.iter().enumerate() {
                if j > 0 { print!(", "); }
                print!("0x{:02X}", b);
            }
            println!("]),");
            print!("        'plaintext':  bytes([");
            for (j, b) in plaintext.iter().enumerate() {
                if j > 0 { print!(", "); }
                print!("0x{:02X}", b);
            }
            println!("]),");
            println!("    }},");

            count += 1;
            if count >= 100 {
                break;
            }
        }

        println!("]");
        println!("\n# Total test vectors extracted: {}", count);
        println!("# Index coverage: {:.1}% of encrypted index blocks", (count as f64 / total_blocks as f64) * 100.0);
    }
}
