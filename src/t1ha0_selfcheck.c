/*
 *  Copyright (c) 2016-2020 Positive Technologies, https://www.ptsecurity.com,
 *  Fast Positive Hash.
 *
 *  Portions Copyright (c) 2010-2020 Leonid Yuriev <leo@yuriev.ru>,
 *  The 1Hippeus project (t1h).
 *
 *  This software is provided 'as-is', without any express or implied
 *  warranty. In no event will the authors be held liable for any damages
 *  arising from the use of this software.
 *
 *  Permission is granted to anyone to use this software for any purpose,
 *  including commercial applications, and to alter it and redistribute it
 *  freely, subject to the following restrictions:
 *
 *  1. The origin of this software must not be misrepresented; you must not
 *     claim that you wrote the original software. If you use this software
 *     in a product, an acknowledgement in the product documentation would be
 *     appreciated but is not required.
 *  2. Altered source versions must be plainly marked as such, and must not be
 *     misrepresented as being the original software.
 *  3. This notice may not be removed or altered from any source distribution.
 */

/*
 * t1ha = { Fast Positive Hash, aka "Позитивный Хэш" }
 * by [Positive Technologies](https://www.ptsecurity.ru)
 *
 * Briefly, it is a 64-bit Hash Function:
 *  1. Created for 64-bit little-endian platforms, in predominantly for x86_64,
 *     but portable and without penalties it can run on any 64-bit CPU.
 *  2. In most cases up to 15% faster than City64, xxHash, mum-hash, metro-hash
 *     and all others portable hash-functions (which do not use specific
 *     hardware tricks).
 *  3. Not suitable for cryptography.
 *
 * The Future will (be) Positive. Всё будет хорошо.
 *
 * ACKNOWLEDGEMENT:
 * The t1ha was originally developed by Leonid Yuriev (Леонид Юрьев)
 * for The 1Hippeus project - zerocopy messaging in the spirit of Sparta!
 */

#ifndef T1HA0_DISABLED
#include "t1ha_bits.h"
#include "t1ha_selfcheck.h"

/* *INDENT-OFF* */
/* clang-format off */

const uint64_t t1ha_refval_32le[81] = { 0,
  0xC92229C10FAEA50E, 0x3DF1354B0DFDC443, 0x968F016D60417BB3, 0x85AAFB50C6DA770F,
  0x66CCE3BB6842C7D6, 0xDDAA39C11537C226, 0x35958D281F0C9C8C, 0x8C5D64B091DE608E,
  0x4094DF680D39786B, 0x1014F4AA2A2EDF4D, 0x39D21891615AA310, 0x7EF51F67C398C7C4,
  0x06163990DDBF319D, 0xE229CAA00C8D6F3F, 0xD2240B4B0D54E0F5, 0xEA2E7E905DDEAF94,
  0x8D4F8A887183A5CE, 0x44337F9A63C5820C, 0x94938D1E86A9B797, 0x96E9CABA5CA210CC,
  0x6EFBB9CC9E8F7708, 0x3D12EA0282FB8BBC, 0x5DA781EE205A2C48, 0xFA4A51A12677FE12,
  0x81D5F04E20660B28, 0x57258D043BCD3841, 0x5C9BEB62059C1ED2, 0x57A02162F9034B33,
  0xBA2A13E457CE19B8, 0xE593263BF9451F3A, 0x0BC1175539606BC5, 0xA3E2929E9C5F289F,
  0x86BDBD06835E35F7, 0xA180950AB48BAADC, 0x7812C994D9924028, 0x308366011415F46B,
  0x77FE9A9991C5F959, 0x925C340B70B0B1E3, 0xCD9C5BA4C41E2E10, 0x7CC4E7758B94CD93,
  0x898B235962EA4625, 0xD7E3E5BF22893286, 0x396F4CDD33056C64, 0x740AB2E32F17CD9F,
  0x60D12FF9CD15B321, 0xBEE3A6C9903A81D8, 0xB47040913B33C35E, 0x19EE8C2ACC013CFF,
  0x5DEC94C5783B55C4, 0x78DC122D562C5F1D, 0x6520F008DA1C181E, 0x77CAF155A36EBF7C,
  0x0A09E02BDB883CA6, 0xFD5D9ADA7E3FB895, 0xC6F5FDD9EEAB83B5, 0x84589BB29F52A92A,
  0x9B2517F13F8E9814, 0x6F752AF6A52E31EC, 0x8E717799E324CE8A, 0x84D90AEF39262D58,
  0x79C27B13FC28944D, 0xE6D6DF6438E0044A, 0x51B603E400D79CA4, 0x6A902B28C588B390,
  0x8D7F8DE9E6CB1D83, 0xCF1A4DC11CA7F044, 0xEF02E43C366786F1, 0x89915BCDBCFBE30F,
  0x5928B306F1A9CC7F, 0xA8B59092996851C5, 0x22050A20427E8B25, 0x6E6D64018941E7EE,
  0x9798C898B81AE846, 0x80EF218CDC30124A, 0xFCE45E60D55B0284, 0x4010E735D3147C35,
  0xEB647D999FD8DC7E, 0xD3544DCAB14FE907, 0xB588B27D8438700C, 0xA49EBFC43E057A4C
};

const uint64_t t1ha_refval_32be[81] = { 0,
  0xC92229C10FAEA50E, 0x0FE212630DD87E0F, 0x968F016D60417BB3, 0xE6B12B2C889913AB,
  0xAA3787887A9DA368, 0x06EE7202D53CEF39, 0x6149AFB2C296664B, 0x86C893210F9A5805,
  0x8379E5DA988AA04C, 0x24763AA7CE411A60, 0x9CF9C64B395A4CF8, 0xFFC192C338DDE904,
  0x094575BAB319E5F5, 0xBBBACFE7728C6511, 0x36B8C3CEBE4EF409, 0xAA0BA8A3397BA4D0,
  0xF9F85CF7124EE653, 0x3ADF4F7DF2A887AE, 0xAA2A0F5964AA9A7A, 0xF18B563F42D36EB8,
  0x034366CEF8334F5C, 0xAE2E85180E330E5F, 0xA5CE9FBFDF5C65B8, 0x5E509F25A9CA9B0B,
  0xE30D1358C2013BD2, 0xBB3A04D5EB8111FE, 0xB04234E82A15A28D, 0x87426A56D0EA0E2F,
  0x095086668E07F9F8, 0xF4CD3A43B6A6AEA5, 0x73F9B9B674D472A6, 0x558344229A1E4DCF,
  0x0AD4C95B2279181A, 0x5E3D19D80821CA6B, 0x652492D25BEBA258, 0xEFA84B02EAB849B1,
  0x81AD2D253059AC2C, 0x1400CCB0DFB2F457, 0x5688DC72A839860E, 0x67CC130E0FD1B0A7,
  0x0A851E3A94E21E69, 0x2EA0000B6A073907, 0xAE9776FF9BF1D02E, 0xC0A96B66B160631C,
  0xA93341DE4ED7C8F0, 0x6FBADD8F5B85E141, 0xB7D295F1C21E0CBA, 0x6D6114591B8E434F,
  0xF5B6939B63D97BE7, 0x3C80D5053F0E5DB4, 0xAC520ACC6B73F62D, 0xD1051F5841CF3966,
  0x62245AEA644AE760, 0x0CD56BE15497C62D, 0x5BB93435C4988FB6, 0x5FADB88EB18DB512,
  0xC897CAE2242475CC, 0xF1A094EF846DC9BB, 0x2B1D8B24924F79B6, 0xC6DF0C0E8456EB53,
  0xE6A40128303A9B9C, 0x64D37AF5EFFA7BD9, 0x90FEB70A5AE2A598, 0xEC3BA5F126D9FF4B,
  0x3121C8EC3AC51B29, 0x3B41C4D422166EC1, 0xB4878DDCBF48ED76, 0x5CB850D77CB762E4,
  0x9A27A43CC1DD171F, 0x2FDFFC6F99CB424A, 0xF54A57E09FDEA7BB, 0x5F78E5EE2CAB7039,
  0xB8BA95883DB31CBA, 0x131C61EB84AF86C3, 0x84B1F64E9C613DA7, 0xE94C1888C0C37C02,
  0xEA08F8BFB2039CDE, 0xCCC6D04D243EC753, 0x8977D105298B0629, 0x7AAA976494A5905E
};

#if T1HA0_AESNI_AVAILABLE || T1HA0_NEON_AVAILABLE
const uint64_t t1ha_refval_ia32aes_a[81] = { 0,
  0x772C7311BE32FF42, 0xB231AC660E5B23B5, 0x71F6DF5DA3B4F532, 0x555859635365F660,
  0xE98808F1CD39C626, 0x2EB18FAF2163BB09, 0x7B9DD892C8019C87, 0xE2B1431C4DA4D15A,
  0x1984E718A5477F70, 0x08DD17B266484F79, 0x4C83A05D766AD550, 0x92DCEBB131D1907D,
  0xD67BC6FC881B8549, 0xF6A9886555FBF66B, 0x6E31616D7F33E25E, 0x36E31B7426E3049D,
  0x4F8E4FAF46A13F5F, 0x03EB0CB3253F819F, 0x636A7769905770D2, 0x3ADF3781D16D1148,
  0x92D19CB1818BC9C2, 0x283E68F4D459C533, 0xFA83A8A88DECAA04, 0x8C6F00368EAC538C,
  0x7B66B0CF3797B322, 0x5131E122FDABA3FF, 0x6E59FF515C08C7A9, 0xBA2C5269B2C377B0,
  0xA9D24FD368FE8A2B, 0x22DB13D32E33E891, 0x7B97DFC804B876E5, 0xC598BDFCD0E834F9,
  0xB256163D3687F5A7, 0x66D7A73C6AEF50B3, 0xBB34C6A4396695D2, 0x7F46E1981C3256AD,
  0x4B25A9B217A6C5B4, 0x7A0A6BCDD2321DA9, 0x0A1F55E690A7B44E, 0x8F451A91D7F05244,
  0x624D5D3C9B9800A7, 0x09DDC2B6409DDC25, 0x3E155765865622B6, 0x96519FAC9511B381,
  0x512E58482FE4FBF0, 0x1AB260EA7D54AE1C, 0x67976F12CC28BBBD, 0x0607B5B2E6250156,
  0x7E700BEA717AD36E, 0x06A058D9D61CABB3, 0x57DA5324A824972F, 0x1193BA74DBEBF7E7,
  0xC18DC3140E7002D4, 0x9F7CCC11DFA0EF17, 0xC487D6C20666A13A, 0xB67190E4B50EF0C8,
  0xA53DAA608DF0B9A5, 0x7E13101DE87F9ED3, 0x7F8955AE2F05088B, 0x2DF7E5A097AD383F,
  0xF027683A21EA14B5, 0x9BB8AEC3E3360942, 0x92BE39B54967E7FE, 0x978C6D332E7AFD27,
  0xED512FE96A4FAE81, 0x9E1099B8140D7BA3, 0xDFD5A5BE1E6FE9A6, 0x1D82600E23B66DD4,
  0x3FA3C3B7EE7B52CE, 0xEE84F7D2A655EF4C, 0x2A4361EC769E3BEB, 0x22E4B38916636702,
  0x0063096F5D39A115, 0x6C51B24DAAFA5434, 0xBAFB1DB1B411E344, 0xFF529F161AE0C4B0,
  0x1290EAE3AC0A686F, 0xA7B0D4585447D1BE, 0xAED3D18CB6CCAD53, 0xFC73D46F8B41BEC6
};

const uint64_t t1ha_refval_ia32aes_b[81] = { 0,
  0x772C7311BE32FF42, 0x4398F62A8CB6F72A, 0x71F6DF5DA3B4F532, 0x555859635365F660,
  0xE98808F1CD39C626, 0x2EB18FAF2163BB09, 0x7B9DD892C8019C87, 0xE2B1431C4DA4D15A,
  0x1984E718A5477F70, 0x08DD17B266484F79, 0x4C83A05D766AD550, 0x92DCEBB131D1907D,
  0xD67BC6FC881B8549, 0xF6A9886555FBF66B, 0x6E31616D7F33E25E, 0x36E31B7426E3049D,
  0x4F8E4FAF46A13F5F, 0x03EB0CB3253F819F, 0x636A7769905770D2, 0x3ADF3781D16D1148,
  0x92D19CB1818BC9C2, 0x283E68F4D459C533, 0xFA83A8A88DECAA04, 0x8C6F00368EAC538C,
  0x7B66B0CF3797B322, 0x5131E122FDABA3FF, 0x6E59FF515C08C7A9, 0xBA2C5269B2C377B0,
  0xA9D24FD368FE8A2B, 0x22DB13D32E33E891, 0x7B97DFC804B876E5, 0xC598BDFCD0E834F9,
  0xB256163D3687F5A7, 0x66D7A73C6AEF50B3, 0xE810F88E85CEA11A, 0x4814F8F3B83E4394,
  0x9CABA22D10A2F690, 0x0D10032511F58111, 0xE9A36EF5EEA3CD58, 0xC79242DE194D9D7C,
  0xC3871AA0435EE5C8, 0x52890BED43CCF4CD, 0x07A1D0861ACCD373, 0x227B816FF0FEE9ED,
  0x59FFBF73AACFC0C4, 0x09AB564F2BEDAD0C, 0xC05F744F2EE38318, 0x7B50B621D547C661,
  0x0C1F71CB4E68E5D1, 0x0E33A47881D4DBAA, 0xF5C3BF198E9A7C2E, 0x16328FD8C0F68A91,
  0xA3E399C9AB3E9A59, 0x163AE71CBCBB18B8, 0x18F17E4A8C79F7AB, 0x9250E2EA37014B45,
  0x7BBBB111D60B03E4, 0x3DAA4A3071A0BD88, 0xA28828D790A2D6DC, 0xBC70FC88F64BE3F1,
  0xA3E48008BA4333C7, 0x739E435ACAFC79F7, 0x42BBB360BE007CC6, 0x4FFB6FD2AF74EC92,
  0x2A799A2994673146, 0xBE0A045B69D48E9F, 0x549432F54FC6A278, 0x371D3C60369FC702,
  0xDB4557D415B08CA7, 0xE8692F0A83850B37, 0x022E46AEB36E9AAB, 0x117AC9B814E4652D,
  0xA361041267AE9048, 0x277CB51C961C3DDA, 0xAFFC96F377CB8A8D, 0x83CC79FA01DD1BA7,
  0xA494842ACF4B802C, 0xFC6D9CDDE2C34A3F, 0x4ED6863CE455F7A7, 0x630914D0DB7AAE98
};
#endif /* T1HA0_AESNI_AVAILABLE */

/* *INDENT-ON* */
/* clang-format on */

__cold int t1ha_selfcheck__t1ha0_32le(void) {
  return t1ha_selfcheck(t1ha0_32le, t1ha_refval_32le);
}

__cold int t1ha_selfcheck__t1ha0_32be(void) {
  return t1ha_selfcheck(t1ha0_32be, t1ha_refval_32be);
}

#if T1HA0_AESNI_AVAILABLE
__cold int t1ha_selfcheck__t1ha0_ia32aes_noavx(void) {
  return t1ha_selfcheck(t1ha0_ia32aes_noavx, t1ha_refval_ia32aes_a);
}

__cold int t1ha_selfcheck__t1ha0_ia32aes_avx(void) {
  return t1ha_selfcheck(t1ha0_ia32aes_avx, t1ha_refval_ia32aes_a);
}

#ifndef __e2k__
__cold int t1ha_selfcheck__t1ha0_ia32aes_avx2(void) {
  return t1ha_selfcheck(t1ha0_ia32aes_avx2, t1ha_refval_ia32aes_b);
}
#endif /* ! __e2k__ */
#endif /* if T1HA0_AESNI_AVAILABLE */

#if T1HA0_NEON_AVAILABLE
__cold int t1ha_selfcheck__t1ha0_aes_neon(void) {
  return t1ha_selfcheck(t1ha0_arm64aes_neon, t1ha_refval_ia32aes_a);
}
#endif


__cold int t1ha_selfcheck__t1ha0(void) {
  int rc = t1ha_selfcheck__t1ha0_32le() | t1ha_selfcheck__t1ha0_32be();

#if (UINTPTR_MAX > 0xffffFFFFul || ULONG_MAX > 0xffffFFFFul) &&                \
    (!defined(T1HA1_DISABLED) || !defined(T1HA2_DISABLED))
#if defined(T1HA1_DISABLED)
  rc |= t1ha_selfcheck__t1ha2();
#else
  rc |= t1ha_selfcheck__t1ha1();
#endif /* T1HA1_DISABLED */
#endif /* 32/64 */

#if T1HA0_AESNI_AVAILABLE
#ifdef __e2k__
  rc |= t1ha_selfcheck__t1ha0_ia32aes_noavx();
  rc |= t1ha_selfcheck__t1ha0_ia32aes_avx();
#else
  uint64_t features = t1ha_ia32cpu_features();
  if (t1ha_ia32_AESNI_avail(features)) {
    rc |= t1ha_selfcheck__t1ha0_ia32aes_noavx();
    if (t1ha_ia32_AVX_avail(features)) {
      rc |= t1ha_selfcheck__t1ha0_ia32aes_avx();
      if (t1ha_ia32_AVX2_avail(features))
        rc |= t1ha_selfcheck__t1ha0_ia32aes_avx2();
    }
  }
#endif /* __e2k__ */
#endif /* T1HA0_AESNI_AVAILABLE */
#if T1HA0_NEON_AVAILABLE
  rc |= t1ha_selfcheck__t1ha0_aes_neon();
#endif

  return rc;
}

#endif /* T1HA0_DISABLED */
