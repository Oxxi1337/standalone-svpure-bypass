#pragma once

#include "hooking/detour.hpp"

namespace Hooks {
    inline CDetourHook SendNetMSG;
    inline CDetourHook UnverifiedFileHashes;
    inline CDetourHook ThirdPartyLoad;
    inline CDetourHook LooseFiles;
}