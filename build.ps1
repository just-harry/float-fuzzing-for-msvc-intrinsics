
<# SPDX-LICENSE-IDENTIFIER: 0BSD #>

<#
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
#>

[CmdletBinding()]
Param (
	[Parameter(Mandatory)] $MSVCIntrinsicsPath,
	[Parameter(Mandatory)] [ValidateSet('dmd', 'ldc')] $Compiler,
	[Switch] $ThirtyTwoBit = $Env:VSCMD_ARG_TGT_ARCH -eq 'x86'
)


$ResolvedMSVCIntrinsicsPath = Resolve-Path $MSVCIntrinsicsPath

Push-Location $PSScriptRoot

try
{
	cl /O2 /Oi /c /Foc_wrappers.obj c_wrappers.c

	lib /SUBSYSTEM:WINDOWS c_wrappers.obj

	if ($Compiler -eq 'dmd')
	{
		dmd -preview=dip1000 $(if ($ThirtyTwoBit) {'-m32'} else {'-m64'}) -O -inline -debug -boundscheck=off -g float_fuzzing.d $ResolvedMSVCIntrinsicsPath c_wrappers.lib
	}
	elseif ($Compiler -eq 'ldc')
	{
		ldc2 -preview=dip1000 $(if ($ThirtyTwoBit) {'-m32'} else {'-m64'}) -mcpu=native -O3 -d-debug -boundscheck=off -g float_fuzzing.d $ResolvedMSVCIntrinsicsPath c_wrappers.lib
	}
}
finally
{
	Pop-Location
}
