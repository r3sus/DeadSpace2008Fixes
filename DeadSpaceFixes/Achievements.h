#pragma once

#include <d3d9.h>

namespace Achievements {
	// Hooks the game's live stat/trophy tracker chokepoint (sub_632490) and shows
	// a D3D9 toast whenever a trophies' tier threshold is newly crossed. The raw
	// engine already counts every registered stat event but never grants or shows
	// anything (the UI/achievement-award network was cut in the PC build), so we
	// detect tier crossings ourselves and surface them as toasts.
	void Initialise();
	void OnPresent(IDirect3DDevice9* pDevice);
}
