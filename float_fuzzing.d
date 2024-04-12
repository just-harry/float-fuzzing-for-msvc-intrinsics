
/+ SPDX-LICENSE-IDENTIFIER: 0BSD +/

/+
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
+/

module float_fuzzing;

import core.exception;
import std.algorithm;
import std.parallelism;
import std.random;
import std.stdio;

import msvc_intrinsics :
	_cvt_ftoi_fast, _cvt_ftoll_fast, _cvt_ftoui_fast, _cvt_ftoull_fast,
	_cvt_dtoi_fast, _cvt_dtoll_fast, _cvt_dtoui_fast, _cvt_dtoull_fast,
	_cvt_ftoi_sat, _cvt_ftoll_sat, _cvt_ftoui_sat, _cvt_ftoull_sat,
	_cvt_dtoi_sat, _cvt_dtoll_sat, _cvt_dtoui_sat, _cvt_dtoull_sat,
	_cvt_ftoi_sent, _cvt_ftoll_sent, _cvt_ftoui_sent, _cvt_ftoull_sent,
	_cvt_dtoi_sent, _cvt_dtoll_sent, _cvt_dtoui_sent, _cvt_dtoull_sent,
	_mm_cvtsi64x_ss, _mm_cvtss_si64x;


extern(C) int c_cvt_ftoi_fast (float value) @safe pure nothrow @nogc;
extern(C) long c_cvt_ftoll_fast (float value) @safe pure nothrow @nogc;
extern(C) uint c_cvt_ftoui_fast (float value) @safe pure nothrow @nogc;
extern(C) ulong c_cvt_ftoull_fast (float value) @safe pure nothrow @nogc;
extern(C) int c_cvt_dtoi_fast (double value) @safe pure nothrow @nogc;
extern(C) long c_cvt_dtoll_fast (double value) @safe pure nothrow @nogc;
extern(C) uint c_cvt_dtoui_fast (double value) @safe pure nothrow @nogc;
extern(C) ulong c_cvt_dtoull_fast (double value) @safe pure nothrow @nogc;
extern(C) int c_cvt_ftoi_sat (float value) @safe pure nothrow @nogc;
extern(C) long c_cvt_ftoll_sat (float value) @safe pure nothrow @nogc;
extern(C) uint c_cvt_ftoui_sat (float value) @safe pure nothrow @nogc;
extern(C) ulong c_cvt_ftoull_sat (float value) @safe pure nothrow @nogc;
extern(C) int c_cvt_dtoi_sat (double value) @safe pure nothrow @nogc;
extern(C) long c_cvt_dtoll_sat (double value) @safe pure nothrow @nogc;
extern(C) uint c_cvt_dtoui_sat (double value) @safe pure nothrow @nogc;
extern(C) ulong c_cvt_dtoull_sat (double value) @safe pure nothrow @nogc;
extern(C) int c_cvt_ftoi_sent (float value) @safe pure nothrow @nogc;
extern(C) long c_cvt_ftoll_sent (float value) @safe pure nothrow @nogc;
extern(C) uint c_cvt_ftoui_sent (float value) @safe pure nothrow @nogc;
extern(C) ulong c_cvt_ftoull_sent (float value) @safe pure nothrow @nogc;
extern(C) int c_cvt_dtoi_sent (double value) @safe pure nothrow @nogc;
extern(C) long c_cvt_dtoll_sent (double value) @safe pure nothrow @nogc;
extern(C) uint c_cvt_dtoui_sent (double value) @safe pure nothrow @nogc;
extern(C) ulong c_cvt_dtoull_sent (double value) @safe pure nothrow @nogc;


auto whyDoesStdTaskToolSwallowErrorsByDefault (const(char)[] failingFunction, Action, OnFailure) (
	scope Action action,
	scope OnFailure onFailure
)
{
	try
	{
		return action();
	}
	catch (AssertError error)
	{
		writefln!("An assertion failed in " ~ failingFunction ~ ": %s:%s: %s")(
			error.file,
			error.line,
			error.message
		);

		return onFailure();
	}
}


int fuzzCD (Float, Target, alias functionC, alias functionD, RNG, Seed) (scope Seed seed)
{
	return whyDoesStdTaskToolSwallowErrorsByDefault!(__traits(identifier, functionD))(
		()
		{
			static if (Float.sizeof == 4)
			{
				alias AsInt = uint;
				alias Significand = uint;
				enum uint significandBitCount = 23;
				enum uint exponentBitCount = 8;
				enum string floatFormat = "08x";
			}
			else static if (Float.sizeof == 8)
			{
				alias AsInt = ulong;
				alias Significand = ulong;
				enum uint significandBitCount = 52;
				enum uint exponentBitCount = 11;
				enum string floatFormat = "016x";
			}

			static if (Target.sizeof == 4)
			{
				enum string intFormat = "08x";
			}
			else static if (Target.sizeof == 8)
			{
				enum string intFormat = "016x";
			}

			enum Significand significandMask = (Significand(1) << significandBitCount) - 1;
			enum Significand quietNaNMask = (Significand(1) << (significandBitCount - 1));
			enum uint signBitOffset = significandBitCount + exponentBitCount;

			enum greatestNumericExponent = (uint(1) << exponentBitCount) - 1;

			static void printFault (Float value, Target answerC, Target answerD)
			{
				writefln!(
					  "0x%4$" ~ floatFormat ~ "; "
					~ __traits(identifier, functionC) ~ "(%1$a) == 0x%2$" ~ intFormat ~  "; "
					~ __traits(identifier, functionD) ~ "(%1$a) == 0x%3$" ~ intFormat
				)(
					value,
					answerC,
					answerD,
					*cast(const(AsInt)*) &value
				);
			}

			static bool faulty (Float value, Target answerC, Target answerD)
			{
				if (answerC != answerD)
				{
					printFault(value, answerC, answerD);
					return true;
				}

				return false;
			}

			auto rng = RNG(seed);

			static if (Float.sizeof == 4)
			{
				AsInt floatAsInt = 0;

				for (;;)
				{
					Target answerC = functionC(*cast(const(Float)*) &floatAsInt);
					Target answerD = functionD(*cast(const(Float)*) &floatAsInt);

					if (faulty(*cast(const(Float)*) &floatAsInt, answerC, answerD))
					{
						return 1;
					}

					++floatAsInt;

					if (floatAsInt == 0)
					{
						break;
					}
				}
			}
			else
			{
				static bool isFaultyForFloat (AsInt floatSansSign)
				{
					foreach (signBit; 0 .. 2)
					{
						AsInt floatAsInt = floatSansSign | (AsInt(signBit) << signBitOffset);
						Float floatValue = *cast(const(Float)*) &floatAsInt;

						Target answerC = functionC(floatValue);
						Target answerD = functionD(floatValue);

						if (faulty(floatValue, answerC, answerD))
						{
							return true;
						}
					}

					return false;
				}

				foreach (biasedExponent; 0 .. (greatestNumericExponent + 1))
				{
					AsInt withExponent = AsInt(biasedExponent) << significandBitCount;

					enum Significand edgeThreshold = Significand(1) << 16;
					enum Significand upperEdgeStart = significandMask - edgeThreshold;

					Significand significand = 0;

					for (;;)
					{
						if (isFaultyForFloat(significand | withExponent))
						{
							return 1;
						}

						if (significand == edgeThreshold)
						{
							break;
						}

						++significand;
					}

					significand = significandMask;

					for (;;)
					{
						if (isFaultyForFloat(significand | withExponent))
						{
							return 1;
						}

						if (significand == upperEdgeStart)
						{
							break;
						}

						--significand;
					}

					enum uint iterationCount = 1 << 16;

					foreach (iteration; 0 .. iterationCount)
					{
						significand = uniform!("[]", Significand)(edgeThreshold, upperEdgeStart, rng);

						if (isFaultyForFloat(significand | withExponent))
						{
							return 1;
						}
					}
				}

				double inf = double.infinity;

				if (isFaultyForFloat(*cast(const(ulong)*) &inf))
				{
					return 1;
				}
			}

			return 0;
		},
		() => 1
	);
}


version (X86_64)
{
	int fuzzCTFELongToFloat (RNG, Seed) (scope Seed seed)
	{
		return whyDoesStdTaskToolSwallowErrorsByDefault!"ctfeX86RoundLongToFloat"(
			()
			{
				static bool isFaultyForLong (ulong longSansSign)
				{
					foreach (signBit; 0 .. 2)
					{
						long asLong = longSansSign | (ulong(signBit) << 63);

						float runtimeAnswer = _mm_cvtsi64x_ss(__vector(float[4]).init, asLong).array[0];
						float ctfeAnswer = __traits(
							getMember,
							__traits(parent, _mm_cvtsi64x_ss),
							"ctfeX86RoundLongToFloat"
						)(
							asLong
						);

						if (runtimeAnswer != ctfeAnswer)
						{
							writefln!(
								"0b%1$064b; _mm_cvtsi64x_ss(%1$d) == 0b%2$032b; ctfeX86RoundLongToFloat(%1$d) == 0b%3$032b"
							)(
								asLong,
								*cast(const(uint)*) &runtimeAnswer,
								*cast(const(uint)*) &ctfeAnswer
							);

							return true;
						}
					}

					return false;
				}

				auto rng = RNG(seed);

				foreach (exponent; 0 .. 63)
				{
					enum ulong iterationCount = ulong(1) << 16;

					ulong base = ulong(1) << exponent;
					ulong nextBase = ulong(1) << (exponent + 1);

					if (exponent <= 16)
					{
						foreach (value; base - 1 .. (ulong(1) << (exponent + 1)) - 1)
						{
							if (isFaultyForLong(value))
							{
								return 1;
							}
						}
					}
					else
					{
						ulong lowerEdge = base + iterationCount;
						ulong upperEdge = nextBase - iterationCount;

						foreach (value; base - 1 .. lowerEdge)
						{
							if (isFaultyForLong(value))
							{
								return 1;
							}
						}

						foreach (value; upperEdge .. nextBase)
						{
							if (isFaultyForLong(value))
							{
								return 1;
							}
						}

						foreach (iteration; 0 .. iterationCount)
						{
							if (isFaultyForLong(uniform!("[]", ulong)(lowerEdge, upperEdge, rng)))
							{
								return 1;
							}
						}
					}
				}

				return 0;
			},
			() => 1
		);
	}


	int fuzzCTFEFloatToLong ()
	{
		return whyDoesStdTaskToolSwallowErrorsByDefault!"ctfeX86RoundFloatToLong"(
			()
			{
				uint floatAsInt = 0;

				for (;;)
				{
					long runtimeAnswer = _mm_cvtss_si64x(*cast(const(float)*) &floatAsInt);
					long ctfeAnswer = __traits(getMember, __traits(parent, _mm_cvtss_si64x), "ctfeX86RoundFloatToLong")(
						*cast(const(float)*) &floatAsInt
					);

					if (runtimeAnswer != ctfeAnswer)
					{
						writefln!"0b%4$032b; _mm_cvtss_si64x(%1$a) == 0x%2$016x; ctfeX86RoundFloatToLong(%1$a) == 0x%3$016x"(
							*cast(const(float)*) &floatAsInt,
							runtimeAnswer,
							ctfeAnswer,
							*cast(const(uint)*) &floatAsInt
						);

						return 1;
					}

					++floatAsInt;

					if (floatAsInt == 0)
					{
						break;
					}
				}

				return 0;
			},
			() => 1
		);
	}
}


int main ()
{
	enum uint rngSeed = 0x1de1aa47;

	scope pool = new TaskPool(totalCPUs);

	//scope t0 = scopedTask(() => fuzzCD!(float, int, c_cvt_ftoi_fast, _cvt_ftoi_fast, Xorshift128)(rngSeed));
	//pool.put(t0);
	scope t1 = scopedTask(() => fuzzCD!(float, long, c_cvt_ftoll_fast, _cvt_ftoll_fast, Xorshift128)(rngSeed));
	pool.put(t1);
	scope t2 = scopedTask(() => fuzzCD!(float, uint, c_cvt_ftoui_fast, _cvt_ftoui_fast, Xorshift128)(rngSeed));
	pool.put(t2);
	scope t3 = scopedTask(() => fuzzCD!(float, ulong, c_cvt_ftoull_fast, _cvt_ftoull_fast, Xorshift128)(rngSeed));
	pool.put(t3);
	scope t4 = scopedTask(() => fuzzCD!(double, int, c_cvt_dtoi_fast, _cvt_dtoi_fast, Xorshift128)(rngSeed));
	pool.put(t4);
	scope t5 = scopedTask(() => fuzzCD!(double, long, c_cvt_dtoll_fast, _cvt_dtoll_fast, Xorshift128)(rngSeed));
	pool.put(t5);
	scope t6 = scopedTask(() => fuzzCD!(double, uint, c_cvt_dtoui_fast, _cvt_dtoui_fast, Xorshift128)(rngSeed));
	pool.put(t6);
	scope t7 = scopedTask(() => fuzzCD!(double, ulong, c_cvt_dtoull_fast, _cvt_dtoull_fast, Xorshift128)(rngSeed));
	pool.put(t7);
	scope t8 = scopedTask(() => fuzzCD!(float, int, c_cvt_ftoi_sat, _cvt_ftoi_sat, Xorshift128)(rngSeed));
	pool.put(t8);
	scope t9 = scopedTask(() => fuzzCD!(float, long, c_cvt_ftoll_sat, _cvt_ftoll_sat, Xorshift128)(rngSeed));
	pool.put(t9);
	scope t10 = scopedTask(() => fuzzCD!(float, uint, c_cvt_ftoui_sat, _cvt_ftoui_sat, Xorshift128)(rngSeed));
	pool.put(t10);
	scope t11 = scopedTask(() => fuzzCD!(float, ulong, c_cvt_ftoull_sat, _cvt_ftoull_sat, Xorshift128)(rngSeed));
	pool.put(t11);
	scope t12 = scopedTask(() => fuzzCD!(double, int, c_cvt_dtoi_sat, _cvt_dtoi_sat, Xorshift128)(rngSeed));
	pool.put(t12);
	scope t13 = scopedTask(() => fuzzCD!(double, long, c_cvt_dtoll_sat, _cvt_dtoll_sat, Xorshift128)(rngSeed));
	pool.put(t13);
	scope t14 = scopedTask(() => fuzzCD!(double, uint, c_cvt_dtoui_sat, _cvt_dtoui_sat, Xorshift128)(rngSeed));
	pool.put(t14);
	scope t15 = scopedTask(() => fuzzCD!(double, ulong, c_cvt_dtoull_sat, _cvt_dtoull_sat, Xorshift128)(rngSeed));
	pool.put(t15);
	//scope t16 = scopedTask(() => fuzzCD!(float, int, c_cvt_ftoi_sent, _cvt_ftoi_sent, Xorshift128)(rngSeed));
	//pool.put(t16);
	scope t17 = scopedTask(() => fuzzCD!(float, long, c_cvt_ftoll_sent, _cvt_ftoll_sent, Xorshift128)(rngSeed));
	pool.put(t17);
	scope t18 = scopedTask(() => fuzzCD!(float, uint, c_cvt_ftoui_sent, _cvt_ftoui_sent, Xorshift128)(rngSeed));
	pool.put(t18);
	scope t19 = scopedTask(() => fuzzCD!(float, ulong, c_cvt_ftoull_sent, _cvt_ftoull_sent, Xorshift128)(rngSeed));
	pool.put(t19);
	scope t20 = scopedTask(() => fuzzCD!(double, int, c_cvt_dtoi_sent, _cvt_dtoi_sent, Xorshift128)(rngSeed));
	pool.put(t20);
	scope t21 = scopedTask(() => fuzzCD!(double, long, c_cvt_dtoll_sent, _cvt_dtoll_sent, Xorshift128)(rngSeed));
	pool.put(t21);
	scope t22 = scopedTask(() => fuzzCD!(double, uint, c_cvt_dtoui_sent, _cvt_dtoui_sent, Xorshift128)(rngSeed));
	pool.put(t22);
	scope t23 = scopedTask(() => fuzzCD!(double, ulong, c_cvt_dtoull_sent, _cvt_dtoull_sent, Xorshift128)(rngSeed));
	pool.put(t23);

	version (X86_64)
	{
		scope t24 = scopedTask(() => fuzzCTFELongToFloat!Xorshift128(rngSeed));
		pool.put(t24);
		scope t25 = scopedTask(&fuzzCTFEFloatToLong);
		pool.put(t25);
	}

	pool.finish(true);

	int code = t1.spinForce | t2.spinForce | t3.spinForce | t4.spinForce | t5.spinForce | t6.spinForce | t7.spinForce | t8.spinForce | t9.spinForce | t10.spinForce | t11.spinForce | t12.spinForce | t13.spinForce | t14.spinForce | t15.spinForce | t17.spinForce | t18.spinForce | t19.spinForce | t20.spinForce | t21.spinForce | t22.spinForce | t23.spinForce;

	version (X86_64)
	{
		code |= t24.spinForce | t25.spinForce;
	}

	writeln(code == 0 ? "It works :)" : "It doesn't work :(");

	return code;
}

