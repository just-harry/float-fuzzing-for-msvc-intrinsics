
/* SPDX-LICENSE-IDENTIFIER: 0BSD */

/*
	BSD Zero Clause License

	Copyright (C) 2024 by Harry Gillanders <contact@harrygillanders.com>

	Permission to use, copy, modify, and/or distribute this software for any
	purpose with or without fee is hereby granted.

	THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
	WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
	MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE
	FOR ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
	WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
	ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
	IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

//long c_cvt_ftoi_fast (float value) {return _cvt_ftoi_fast(value);}
long long c_cvt_ftoll_fast (float value) {return _cvt_ftoll_fast(value);}
unsigned long c_cvt_ftoui_fast (float value) {return _cvt_ftoui_fast(value);}
unsigned long long c_cvt_ftoull_fast (float value) {return _cvt_ftoull_fast(value);}
long c_cvt_dtoi_fast (double value) {return _cvt_dtoi_fast(value);}
long long c_cvt_dtoll_fast (double value) {return _cvt_dtoll_fast(value);}
unsigned long c_cvt_dtoui_fast (double value) {return _cvt_dtoui_fast(value);}
unsigned long long c_cvt_dtoull_fast (double value) {return _cvt_dtoull_fast(value);}
long c_cvt_ftoi_sat (float value) {return _cvt_ftoi_sat(value);}
long long c_cvt_ftoll_sat (float value) {return _cvt_ftoll_sat(value);}
unsigned long c_cvt_ftoui_sat (float value) {return _cvt_ftoui_sat(value);}
unsigned long long c_cvt_ftoull_sat (float value) {return _cvt_ftoull_sat(value);}
long c_cvt_dtoi_sat (double value) {return _cvt_dtoi_sat(value);}
long long c_cvt_dtoll_sat (double value) {return _cvt_dtoll_sat(value);}
unsigned long c_cvt_dtoui_sat (double value) {return _cvt_dtoui_sat(value);}
unsigned long long c_cvt_dtoull_sat (double value) {return _cvt_dtoull_sat(value);}
//long c_cvt_ftoi_sent (float value) {return _cvt_ftoi_sent(value);}
unsigned long c_cvt_ftoui_sent (float value) {return _cvt_ftoui_sent(value);}
unsigned long long c_cvt_ftoull_sent (float value) {return _cvt_ftoull_sent(value);}
long long c_cvt_ftoll_sent (float value) {return _cvt_ftoll_sent(value);}
long c_cvt_dtoi_sent (double value) {return _cvt_dtoi_sent(value);}
long long c_cvt_dtoll_sent (double value) {return _cvt_dtoll_sent(value);}
unsigned long c_cvt_dtoui_sent (double value) {return _cvt_dtoui_sent(value);}
unsigned long long c_cvt_dtoull_sent (double value) {return _cvt_dtoull_sent(value);}

