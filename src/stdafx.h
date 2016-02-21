#pragma once


///NODEFAULTLIB /DYNAMICBASE:NO /MANIFEST:NO /MERGE:.rdata=.text

#pragma comment(linker, " /BASE:0")

#define GAME_DLL
#define CLIENT_DLL

#define NET_MESSAGE_BITS 6

#define WIN32_LEAN_AND_MEAN
#define VC_EXTRALEAN
#define _CRT_SECURE_NO_WARNINGS

#include "targetver.h"


// Windows Header Files:
#include <windows.h>
#include <stdio.h>
#include <iostream>
#include <sstream>
#include <fstream>
#include <string>
#include <ctime>