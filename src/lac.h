#pragma once

#include "stdafx.h"
#include "vmthook.h"
#include "sdk.h"

namespace LAC
{
	int Init();
	int Detach();

	bool Initiated;
};