#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <d3d9.h>
#include <string>
#include <vector>
#include <cstdio>
#include <cstring>

#include "Achievements.h"
#include "Utils.h"
#include "Config.h"
#include "MinHook/MinHook.h"

namespace Achievements {

	// ---------------------------------------------------------------------------
	// Engine function addresses (found via pattern scan at init)
	// ---------------------------------------------------------------------------
	static uintptr_t s_trackerHandler = 0;  // sub_632490  (this=tracker, arg0=msg)
	static uintptr_t s_stringHash = 0;      // sub_6C2010  (edx=name -> eax=hash)

	// Original sub_632490 trampoline (thiscall -> __fastcall detour).
	static unsigned int(__fastcall* s_oTrackerHandler)(void* thisptr, void* /*edx*/, void* msg) = nullptr;

	// ---------------------------------------------------------------------------
	// Registered trophy events (mirrors the engine's sub_631DA0 registration).
	// slot layout (tracker + 0x6C, stride 0x2C): +8..+20 = thresholds (-1 sentinel),
	// +24..+36 = trophy IDs, +40 = reset flag.
	// ---------------------------------------------------------------------------
	struct TrophyDef {
		const char* msg;
		const char* name;
		int thresholds[4];
		int trophies[4];
		bool enabled;
	};

	static TrophyDef s_trophies[] = {
		{ "iMsgLaunchTK",                  "Pusher",                   { 50, 0, 0, 0 },        { 113, 0, 0, 0 },   true },
		{ "iMsgLurkerPairedKill",          "Live With The Locals",     { 10, 0, 0, 0 },        { 115, 0, 0, 0 },   true },
		{ "iMsgZoneDismembered",           "Crack Shot",               { 1000, 500, 20, 0 },   { 118, 117, 116, 0 }, true },
		{ "iMsgStasisEnemy",               "Freeze",                   { 50, 0, 0, 0 },        { 119, 0, 0, 0 },   true },
		{ "iMsgZGJump",                    "Eccentric",                { 100, 0, 0, 0 },       { 122, 0, 0, 0 },   true },
		{ "iMsgGunFireScoring",            "",                         { 0, 0, 0, 0 },         { 0, 0, 0, 0 },     false },
		{ "iMsgScoringKill_Melee",         "Tool Time",                { 30, 0, 0, 0 },        { 124, 0, 0, 0 },   true },
		{ "iMsgCreditsSpent",              "Shopaholic",               { 200000, 0, 0, 0 },    { 127, 0, 0, 0 },   true },
		{ "iMsgScoringKill_Contact Beam",  "Contact Beam: 30 Kills",   { 30, 0, 0, 0 },        { 129, 0, 0, 0 },   true },
		{ "iMsgScoringKill_Ripper",        "Ripper: 30 Kills",         { 30, 0, 0, 0 },        { 130, 0, 0, 0 },   true },
		{ "iMsgScoringKill_Plasma Cutter","Plasma Cutter: 30 Kills",   { 30, 0, 0, 0 },        { 131, 0, 0, 0 },   true },
		{ "iMsgScoringKill_Force Gun",     "Force Gun: 30 Kills",      { 30, 0, 0, 0 },        { 132, 0, 0, 0 },   true },
		{ "iMsgScoringKill_Flamethrower",  "Flamethrower: 30 Kills",   { 30, 0, 0, 0 },        { 133, 0, 0, 0 },   true },
		{ "iMsgScoringKill_Pulse Rifle",   "Pulse Rifle: 30 Kills",    { 30, 0, 0, 0 },        { 134, 0, 0, 0 },   true },
		{ "iMsgScoringKill_Line Gun",      "Line Gun: 30 Kills",       { 30, 0, 0, 0 },        { 135, 0, 0, 0 },   true },
		{ "iMsgStoreSafe",                 "Bank Account",             { 25, 0, 0, 0 },        { 107, 0, 0, 0 },   true },
		{ "iMsgCollectLog",                "Full Clearance",           { 150, 75, 0, 0 },      { 109, 108, 0, 0 }, true },
		{ "iMsgGetWeapon",                 "This Gun is Expensive",    { 7, 0, 0, 0 },         { 110, 0, 0, 0 },   true },
		{ "iMsgGetSchematic",              "Z-Baller",                 { 8, 0, 0, 0 },         { 112, 0, 0, 0 },   true },
		{ "iMsgADSVictoryStep",            "Victory Step",             { 50, 0, 0, 0 },        { 121, 0, 0, 0 },   true },
		{ "iMsgADSVictoryThrown",          "One Gun Is Enough",        { 50, 0, 0, 0 },        { 128, 0, 0, 0 },   true },
		{ "iMsgCompletelyUpgraded",        "The Distinguished",        { 1, 0, 0, 0 },         { 125, 0, 0, 0 },   true },
		{ "iMsgGravTrapKill",              "Entrapment",               { 5, 0, 0, 0 },         { 126, 0, 0, 0 },   true },
	};
	static const int s_trophyCount = (int)(sizeof(s_trophies) / sizeof(s_trophies[0]));

	struct EventState {
		unsigned int hash;
		int counter;
		unsigned int unlockedMask;
	};
	static EventState s_events[s_trophyCount];

	// ---------------------------------------------------------------------------
	// Runtime diagnostics (shown in the on-screen debug panel, see DrawDebugPanel).
	// ---------------------------------------------------------------------------
	static bool s_initRan = false;
	static bool s_patternOk = false;
	static unsigned long s_hookCalls = 0;      // times the tracker handler fired
	static unsigned long s_hashMatches = 0;    // times a watched msg hash matched
	static unsigned int s_seenHashes[16] = {}; // first 16 msg hashes seen live
	static int s_seenHashCount = 0;
	static MH_STATUS s_createHookRes = MH_UNKNOWN;
	static MH_STATUS s_enableHookRes = MH_UNKNOWN;

	// ---------------------------------------------------------------------------
	// Engine hash helper: int __usercall sub_6C2010@<eax>(void* ignored, const char* name@<edx>)
	// ---------------------------------------------------------------------------
	static unsigned int HashName(const char* name)
	{
		if (s_stringHash == 0)
			return 0;
		unsigned int result = 0;
		__asm {
			mov edx, name
			mov ecx, 0
			call dword ptr[s_stringHash]
			mov result, eax
		}
		return result;
	}

	// ---------------------------------------------------------------------------
	// Toast state
	// ---------------------------------------------------------------------------
	struct Toast {
		std::string title;
		std::string desc;
		unsigned long long start;
		float y;
		bool placed;
	};
	static std::vector<Toast> s_toasts;
	static IDirect3DDevice9* s_device = nullptr;

	static void PushToast(const char* title, const char* desc)
	{
		DEBUG_LOG("PushToast: %s", title ? title : "(null)");
		Toast t;
		t.title = title ? title : "";
		t.desc = desc ? desc : "";
		t.start = GetTickCount64();
		t.y = 0.0f;
		t.placed = false;
		s_toasts.push_back(t);
	}

	// ---------------------------------------------------------------------------
	// Tracker handler hook
	// ---------------------------------------------------------------------------
	static unsigned int __fastcall TrackerHandlerHook(void* thisptr, void* /*edx*/, void* msg)
	{
		if (msg == nullptr)
			return s_oTrackerHandler(thisptr, nullptr, msg);

		const unsigned int hash = *reinterpret_cast<unsigned int*>(msg);

		unsigned int result = s_oTrackerHandler(thisptr, nullptr, msg);

		s_hookCalls++;
		if (s_seenHashCount < 16)
			s_seenHashes[s_seenHashCount++] = hash;

		int payload = 1;
		void* payloadPtr = *reinterpret_cast<void**>(reinterpret_cast<char*>(msg) + 4);
		if (payloadPtr != nullptr)
			payload = *reinterpret_cast<int*>(payloadPtr);

		for (int i = 0; i < s_trophyCount; ++i)
		{
			if (s_events[i].hash != hash || !s_trophies[i].enabled)
				continue;

			s_hashMatches++;
			s_events[i].counter += payload;

			for (int tier = 0; tier < 4; ++tier)
			{
				if (s_trophies[i].thresholds[tier] <= 0)
					continue;
				if (s_events[i].counter < s_trophies[i].thresholds[tier])
					continue;
				if (s_events[i].unlockedMask & (1u << tier))
					continue;

				s_events[i].unlockedMask |= (1u << tier);
				if (s_trophies[i].trophies[tier] != 0)
					PushToast(s_trophies[i].name, "Achievement Unlocked");
			}
			break;
		}

		return result;
	}

	// ---------------------------------------------------------------------------
	// Overlay rendering (GDI -> D3D9 texture, dependency-free)
	// ---------------------------------------------------------------------------
	struct QuadVertex { float x, y, z, rhw; DWORD color; float u, v; };
	static const DWORD kFVF = D3DFVF_XYZRHW | D3DFVF_DIFFUSE | D3DFVF_TEX1;

	static IDirect3DTexture9* RenderTextToTexture(const std::string& title, const std::string& desc, int* outW, int* outH)
	{
		if (s_device == nullptr)
			return nullptr;

		HDC dc = CreateCompatibleDC(nullptr);
		if (!dc)
			return nullptr;

		HGDIOBJ oldFont = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
		LOGFONTA lf{};
		lf.lfHeight = -16;
		lf.lfWeight = FW_BOLD;
		strcpy_s(lf.lfFaceName, "Segoe UI");
		HFONT hFont = CreateFontIndirectA(&lf);
		HGDIOBJ old = SelectObject(dc, hFont);

		RECT rc = { 0, 0, 0, 0 };
		RECT titleRc = rc, descRc = rc;
		DrawTextA(dc, title.c_str(), -1, &titleRc, DT_CALCRECT | DT_SINGLELINE);
		DrawTextA(dc, desc.c_str(), -1, &descRc, DT_CALCRECT | DT_SINGLELINE);

		const int pad = 12;
		int txtW = titleRc.right > descRc.right ? titleRc.right : descRc.right;
		int contentH = titleRc.bottom + descRc.bottom;
		int w = txtW + pad * 2;
		int h = contentH + pad * 2;
		if (w < 1) w = 1;
		if (h < 1) h = 1;

		// 32bpp top-down DIB.
		BITMAPINFO bmi{};
		bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bmi.bmiHeader.biWidth = w;
		bmi.bmiHeader.biHeight = -h; // top-down
		bmi.bmiHeader.biPlanes = 1;
		bmi.bmiHeader.biBitCount = 32;
		bmi.bmiHeader.biCompression = BI_RGB;
		void* bits = nullptr;
		HBITMAP dib = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
		HGDIOBJ oldBmp = SelectObject(dc, dib);

		// Transparent background.
		RECT full = { 0, 0, w, h };
		HBRUSH trans = CreateSolidBrush(RGB(0, 0, 0));
		FillRect(dc, &full, trans);
		DeleteObject(trans);

		SetBkMode(dc, TRANSPARENT);
		SetTextColor(dc, RGB(255, 210, 90));
		RECT tl = { pad, pad, w - pad, pad + titleRc.bottom };
		DrawTextA(dc, title.c_str(), -1, &tl, DT_LEFT | DT_SINGLELINE);
		SetTextColor(dc, RGB(235, 235, 235));
		RECT dl = { pad, pad + titleRc.bottom, w - pad, h - pad };
		DrawTextA(dc, desc.c_str(), -1, &dl, DT_LEFT | DT_SINGLELINE);

		// Convert 32-bit BGRA DIB (top-down) to A8R8G8B8 texture.
		std::vector<BYTE> alpha(w * h);
		std::vector<BYTE> rgba(w * h * 4);
		const BYTE* src = (const BYTE*)bits;
		for (int y = 0; y < h; ++y)
		{
			for (int x = 0; x < w; ++x)
			{
				int si = (y * w + x) * 4;
				BYTE b = src[si + 0], g = src[si + 1], r = src[si + 2];
				// Key out pure black background.
				BYTE a = (r < 24 && g < 24 && b < 24) ? 0 : 255;
				alpha[(y) * w + x] = a;
				int di = (y * w + x) * 4;
				rgba[di + 0] = b;
				rgba[di + 1] = g;
				rgba[di + 2] = r;
				rgba[di + 3] = a;
			}
		}

		IDirect3DTexture9* tex = nullptr;
		if (SUCCEEDED(s_device->CreateTexture(w, h, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &tex, nullptr)))
		{
			D3DLOCKED_RECT lr;
			if (SUCCEEDED(tex->LockRect(0, &lr, nullptr, 0)))
			{
				for (int y = 0; y < h; ++y)
					memcpy((BYTE*)lr.pBits + y * lr.Pitch, &rgba[y * w * 4], w * 4);
				tex->UnlockRect(0);
			}
		}

		SelectObject(dc, oldBmp);
		SelectObject(dc, old);
		SelectObject(dc, oldFont);
		DeleteObject(hFont);
		DeleteObject(dib);
		DeleteDC(dc);

		if (outW) *outW = w;
		if (outH) *outH = h;
		return tex;
	}

	static void DrawTexturedQuad(float x, float y, float w, float h, IDirect3DTexture9* tex, DWORD color, float alpha)
	{
		if (tex == nullptr || s_device == nullptr)
			return;

		IDirect3DVertexBuffer9* vb = nullptr;
		if (FAILED(s_device->CreateVertexBuffer(sizeof(QuadVertex) * 4, D3DUSAGE_DYNAMIC | D3DUSAGE_WRITEONLY, kFVF, D3DPOOL_DEFAULT, &vb, nullptr)))
			return;

		DWORD finalColor = D3DCOLOR_ARGB((DWORD)(alpha * 255.0f), (color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF);
		QuadVertex v[4] = {
			{ x, y, 0, 1, finalColor, 0, 0 },
			{ x + w, y, 0, 1, finalColor, 1, 0 },
			{ x + w, y + h, 0, 1, finalColor, 1, 1 },
			{ x, y + h, 0, 1, finalColor, 0, 1 },
		};

		QuadVertex* p = nullptr;
		if (SUCCEEDED(vb->Lock(0, sizeof(v), (void**)&p, D3DLOCK_DISCARD)))
		{
			memcpy(p, v, sizeof(v));
			vb->Unlock();

			s_device->SetFVF(kFVF);
			s_device->SetStreamSource(0, vb, 0, sizeof(QuadVertex));
			s_device->SetTexture(0, tex);
			s_device->SetTextureStageState(0, D3DTSS_COLOROP, D3DTOP_MODULATE);
			s_device->SetTextureStageState(0, D3DTSS_COLORARG1, D3DTA_TEXTURE);
			s_device->SetTextureStageState(0, D3DTSS_COLORARG2, D3DTA_DIFFUSE);
			s_device->SetTextureStageState(0, D3DTSS_ALPHAOP, D3DTOP_MODULATE);
			s_device->SetTextureStageState(0, D3DTSS_ALPHAARG1, D3DTA_TEXTURE);
			s_device->SetTextureStageState(0, D3DTSS_ALPHAARG2, D3DTA_DIFFUSE);
			s_device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
			s_device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
			s_device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
			s_device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
			s_device->SetRenderState(D3DRS_LIGHTING, FALSE);
			s_device->SetRenderState(D3DRS_ZENABLE, FALSE);

			s_device->DrawPrimitive(D3DPT_TRIANGLEFAN, 0, 2);
		}
		vb->Release();
	}

	static void DrawSolidQuad(float x, float y, float w, float h, DWORD color)
	{
		if (s_device == nullptr)
			return;

		struct V { float x, y, z, rhw; DWORD color; };
		IDirect3DVertexBuffer9* vb = nullptr;
		if (FAILED(s_device->CreateVertexBuffer(sizeof(V) * 4, D3DUSAGE_DYNAMIC | D3DUSAGE_WRITEONLY, D3DFVF_XYZRHW | D3DFVF_DIFFUSE, D3DPOOL_DEFAULT, &vb, nullptr)))
			return;

		V v[4] = {
			{ x, y, 0, 1, color }, { x + w, y, 0, 1, color },
			{ x + w, y + h, 0, 1, color }, { x, y + h, 0, 1, color },
		};
		V* p = nullptr;
		if (SUCCEEDED(vb->Lock(0, sizeof(v), (void**)&p, D3DLOCK_DISCARD)))
		{
			memcpy(p, v, sizeof(v));
			vb->Unlock();
			s_device->SetFVF(D3DFVF_XYZRHW | D3DFVF_DIFFUSE);
			s_device->SetStreamSource(0, vb, 0, sizeof(V));
			s_device->SetTexture(0, nullptr);
			s_device->SetRenderState(D3DRS_ALPHABLENDENABLE, TRUE);
			s_device->SetRenderState(D3DRS_SRCBLEND, D3DBLEND_SRCALPHA);
			s_device->SetRenderState(D3DRS_DESTBLEND, D3DBLEND_INVSRCALPHA);
			s_device->SetRenderState(D3DRS_CULLMODE, D3DCULL_NONE);
			s_device->SetRenderState(D3DRS_ZENABLE, FALSE);
			s_device->SetRenderState(D3DRS_LIGHTING, FALSE);
			s_device->DrawPrimitive(D3DPT_TRIANGLEFAN, 0, 2);
		}
		vb->Release();
	}

	static void DrawToasts(float screenW, float screenH)
	{
		if (s_toasts.empty() || s_device == nullptr)
			return;

		const unsigned long long kTotalMs = 6000;
		const unsigned long long kSlideMs = 350;
		const unsigned long long kHoldMs = 5000;
		unsigned long long now = GetTickCount64();

		for (size_t i = 0; i < s_toasts.size(); )
		{
			if (now - s_toasts[i].start >= kTotalMs)
				s_toasts.erase(s_toasts.begin() + i);
			else
				++i;
		}
		if (s_toasts.empty())
			return;

		const float scale = screenH >= 1080.0f ? screenH / 1080.0f : 1.0f;
		const float toastW = 460.0f * scale;
		const float margin = 20.0f * scale;
		const float spacing = 8.0f * scale;
		const float onX = screenW - toastW - margin;
		const float offX = screenW + 30.0f;

		float targetY = margin;
		for (Toast& to : s_toasts)
		{
			float t = (float)(now - to.start);
			float x, alpha;
			if (t < (float)kSlideMs)
			{
				float k = t / (float)kSlideMs;
				k = 1.0f - (1.0f - k) * (1.0f - k);
				x = offX + (onX - offX) * k;
				alpha = k;
			}
			else if (t < (float)kHoldMs)
			{
				x = onX;
				alpha = 1.0f;
			}
			else
			{
				float k = (t - (float)kHoldMs) / ((float)kTotalMs - (float)kHoldMs);
				x = onX + (offX - onX) * (k * k);
				alpha = 1.0f - k;
			}

			if (!to.placed)
			{
				to.y = targetY;
				to.placed = true;
			}
			else
			{
				to.y += (targetY - to.y) * 0.25f;
			}

			int tw = 0, th = 0;
			IDirect3DTexture9* txtTex = RenderTextToTexture(to.title, to.desc, &tw, &th);

			const float pad = 12.0f * scale;
			const float boxH = th * scale + pad * 2.0f;
			const float boxW = toastW;

			float a = alpha < 0.0f ? 0.0f : (alpha > 1.0f ? 1.0f : alpha);
			DrawSolidQuad(x, to.y, boxW, boxH, D3DCOLOR_ARGB((DWORD)(a * 205), 22, 22, 26));
			DrawSolidQuad(x, to.y, 4.0f * scale, boxH, D3DCOLOR_ARGB((DWORD)(a * 255), 205, 165, 55));

			if (txtTex)
			{
				DrawTexturedQuad(x + pad, to.y + pad, (float)tw * scale, (float)th * scale, txtTex, 0xFFFFFF, a);
				txtTex->Release();
			}

			targetY += boxH + spacing;
		}
	}

	// ---------------------------------------------------------------------------
	// Debug panel (F8 to toggle, F9 to spawn a fake toast)
	// ---------------------------------------------------------------------------
	static bool s_showDebug = false;
	static bool s_f8Prev = false;
	static bool s_f9Prev = false;

	static IDirect3DTexture9* s_panelTex = nullptr;
	static std::string s_panelText;
	static int s_panelW = 0, s_panelH = 0;

	// Multi-line text -> transparent texture (same GDI pipeline as the toasts).
	static IDirect3DTexture9* RenderTextBlock(const std::string& text, int maxW, int* outW, int* outH)
	{
		if (s_device == nullptr)
			return nullptr;

		HDC dc = CreateCompatibleDC(nullptr);
		if (!dc)
			return nullptr;

		HGDIOBJ oldFont = SelectObject(dc, GetStockObject(DEFAULT_GUI_FONT));
		LOGFONTA lf{};
		lf.lfHeight = -14;
		SelectObject(dc, CreateFontIndirectA(&lf));

		RECT rc = { 0, 0, maxW, 0x10000 };
		DrawTextA(dc, text.c_str(), -1, &rc, DT_CALCRECT | DT_LEFT | DT_NOPREFIX);

		const int pad = 10;
		int w = rc.right + pad * 2;
		int h = rc.bottom + pad * 2;
		if (w < 1) w = 1;
		if (h < 1) h = 1;

		BITMAPINFO bmi{};
		bmi.bmiHeader.biSize = sizeof(BITMAPINFOHEADER);
		bmi.bmiHeader.biWidth = w;
		bmi.bmiHeader.biHeight = -h;
		bmi.bmiHeader.biPlanes = 1;
		bmi.bmiHeader.biBitCount = 32;
		bmi.bmiHeader.biCompression = BI_RGB;
		void* bits = nullptr;
		HBITMAP dib = CreateDIBSection(dc, &bmi, DIB_RGB_COLORS, &bits, nullptr, 0);
		HGDIOBJ oldBmp = SelectObject(dc, dib);

		RECT full = { 0, 0, w, h };
		HBRUSH trans = CreateSolidBrush(RGB(0, 0, 0));
		FillRect(dc, &full, trans);
		DeleteObject(trans);

		SetBkMode(dc, TRANSPARENT);
		SetTextColor(dc, RGB(235, 235, 235));
		RECT rr = { pad, pad, w - pad, h - pad };
		DrawTextA(dc, text.c_str(), -1, &rr, DT_LEFT | DT_NOPREFIX);

		std::vector<BYTE> rgba(w * h * 4);
		const BYTE* src = (const BYTE*)bits;
		for (int y = 0; y < h; ++y)
		{
			for (int x = 0; x < w; ++x)
			{
				int si = (y * w + x) * 4;
				BYTE b = src[si + 0], g = src[si + 1], r = src[si + 2];
				BYTE a = (r < 24 && g < 24 && b < 24) ? 0 : 255;
				int di = (y * w + x) * 4;
				rgba[di + 0] = b; rgba[di + 1] = g; rgba[di + 2] = r; rgba[di + 3] = a;
			}
		}

		IDirect3DTexture9* tex = nullptr;
		if (SUCCEEDED(s_device->CreateTexture(w, h, 1, 0, D3DFMT_A8R8G8B8, D3DPOOL_MANAGED, &tex, nullptr)))
		{
			D3DLOCKED_RECT lr;
			if (SUCCEEDED(tex->LockRect(0, &lr, nullptr, 0)))
			{
				for (int y = 0; y < h; ++y)
					memcpy((BYTE*)lr.pBits + y * lr.Pitch, &rgba[y * w * 4], w * 4);
				tex->UnlockRect(0);
			}
		}

		SelectObject(dc, oldBmp);
		DeleteObject(dib);
		DeleteObject(SelectObject(dc, oldFont));
		DeleteDC(dc);

		if (outW) *outW = w;
		if (outH) *outH = h;
		return tex;
	}

	static void DrawDebugPanel(float screenW, float screenH)
	{
		char buf[1536];
		char live[384] = "";
		size_t nl = 0;

		// Compact live list: msgs that have actually matched and their counters.
		for (int i = 0; i < s_trophyCount; ++i)
		{
			if (s_events[i].counter <= 0)
				continue;
			char tmp[160];
			_snprintf_s(tmp, _TRUNCATE, "%s:%d ", s_trophies[i].name, s_events[i].counter);
			if (strlen(live) + strlen(tmp) < sizeof(live))
				strcat_s(live, tmp);
			++nl;
		}
		if (nl == 0)
			strcat_s(live, "(none matched yet)");

		char seen[160] = "";
		{
			char tmp[64];
			for (int i = 0; i < s_seenHashCount; ++i)
			{
				_snprintf_s(tmp, _TRUNCATE, "%08X ", s_seenHashes[i]);
				if (strlen(seen) + strlen(tmp) < sizeof(seen))
					strcat_s(seen, tmp);
			}
			if (s_seenHashCount == 0)
				strcat_s(seen, "(no msg calls yet)");
		}

		_snprintf_s(buf, _TRUNCATE,
			"DeadSpaceFixes -- Achievements debug   [F8 hide | F9 test toast]\n"
			"config=%d init=%d pattern=%d\n"
			"hash@%p  tracker@%p\n"
			"MH create=%d enable=%d   calls=%lu  matches=%lu\n"
			"toasts=%zu   hookFn=%s\n"
			"table: launch=%08X weapon=%08X scoring=%08X getSchem=%08X\n"
			"live: %s\n"
			"seen: %s\n"
			"F9 pushes a fake toast to verify the overlay render path.",
			(int)Config::Achievements, (int)s_initRan, (int)s_patternOk,
			(void*)s_stringHash, (void*)s_trackerHandler,
			(int)s_createHookRes, (int)s_enableHookRes, s_hookCalls, s_hashMatches,
			s_toasts.size(), s_oTrackerHandler ? "OK" : "null",
			s_events[0].hash, HashName("iMsgGetWeapon"), HashName("iMsgGunFireScoring"), HashName("iMsgGetSchematic"),
			live, seen);

		// Rebuild the cached texture only when the text changes.
		if (s_panelTex == nullptr || s_panelText != buf)
		{
			if (s_panelTex)
			{
				s_panelTex->Release();
				s_panelTex = nullptr;
			}
			s_panelTex = RenderTextBlock(buf, 560, &s_panelW, &s_panelH);
			s_panelText = buf;
		}
		if (s_panelTex == nullptr)
			return;

		const float scale = screenH >= 1080.0f ? screenH / 1080.0f : 1.0f;
		const float pad = 10.0f * scale;
		float pw = (float)s_panelW * scale;
		float ph = (float)s_panelH * scale;
		float x = pad;
		float y = pad;

		DrawSolidQuad(x - 2.0f, y - 2.0f, pw + 4.0f, ph + 4.0f, D3DCOLOR_ARGB(215, 14, 14, 18));
		if (s_panelTex)
			DrawTexturedQuad(x, y, pw, ph, s_panelTex, 0xFFFFFF, 1.0f);
	}

	static void HandleDebugKeys()
	{
		bool f8 = (GetAsyncKeyState(VK_F8) & 0x8000) != 0;
		if (f8 && !s_f8Prev)
			s_showDebug = !s_showDebug;
		s_f8Prev = f8;

		bool f9 = (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
		if (f9 && !s_f9Prev)
			PushToast("Test Achievement", "F9 pressed - toast render OK");
		s_f9Prev = f9;
	}

	// ---------------------------------------------------------------------------
	// Init / present
	// ---------------------------------------------------------------------------
	void Initialise()
	{
		DEBUG_LOG("Achievements::Initialise() entered; Config::Achievements=%d", (int)Config::Achievements);
		if (!Config::Achievements)
			return;

		// MinHook must be initialized; already-done is fine (idempotent).
		MH_STATUS initRes = MH_Initialize();
		if (initRes != MH_OK && initRes != MH_ERROR_ALREADY_INITIALIZED)
		{
			DEBUG_LOG("Achievements: MH_Initialize failed %d", (int)initRes);
			return;
		}

		HMODULE hExe = GetModuleHandleA(nullptr);
		if (!hExe)
		{
			DEBUG_LOG("Achievements: GetModuleHandleA failed");
			return;
		}

		s_stringHash = Utils::FindPattern(hExe, "33 C0 85 D2 74 ? 8A 0A 84 C9 74 ? 56 8D 49 ? 0F B6 C9 8D 71 ? 83 C2 01 83 FE 19 77 ? 83 C1 20 69 C0 3F 00 01 00");
		s_trackerHandler = Utils::FindPattern(hExe, "56 8B B1 ? ? ? ? 33 C0 85 F6 76 ? 53");
		s_initRan = true;
		s_patternOk = (s_stringHash != 0 && s_trackerHandler != 0);
		DEBUG_LOG("Achievements: hash@%p tracker@%p", (void*)s_stringHash, (void*)s_trackerHandler);
		if (!s_patternOk)
		{
			DEBUG_LOG("Achievements: engine patterns not found");
			return;
		}

		for (int i = 0; i < s_trophyCount; ++i)
			s_events[i].hash = HashName(s_trophies[i].msg);
		DEBUG_LOG("Achievements: sample hashes launch=%08X weapon=%08X schematic=%08X",
			s_events[0].hash, s_events[11].hash, (int)HashName("iMsgGetSchematic"));

		s_createHookRes = MH_CreateHook(reinterpret_cast<void*>(s_trackerHandler), &TrackerHandlerHook, reinterpret_cast<LPVOID*>(&s_oTrackerHandler));
		if (s_createHookRes == MH_OK)
		{
			s_enableHookRes = MH_EnableHook(reinterpret_cast<void*>(s_trackerHandler));
			DEBUG_LOG("Achievements: tracker handler hooked (enable=%d)", (int)s_enableHookRes);
		}
		else
		{
			DEBUG_LOG("Achievements: MH_CreateHook failed %d", (int)s_createHookRes);
		}
	}

	void OnPresent(IDirect3DDevice9* pDevice)
	{
		static volatile unsigned long presentCalls = 0;
		unsigned long pc = ++presentCalls;
		if (pc <= 2 || (pc % 600) == 0)
			DEBUG_LOG("OnPresent called (#%lu) dev=%p toasts=%zu debug=%d",
				pc, (void*)pDevice, s_toasts.size(), (int)s_showDebug);

		if (!Config::Achievements)
			return;
		if (pDevice == nullptr)
			return;

		s_device = pDevice;
		HandleDebugKeys();
		if (!s_showDebug && s_toasts.empty())
			return;

		IDirect3DSurface9* bb = nullptr;
		D3DSURFACE_DESC d{};
		if (SUCCEEDED(pDevice->GetBackBuffer(0, 0, D3DBACKBUFFER_TYPE_MONO, &bb)) && bb)
		{
			bb->GetDesc(&d);
			bb->Release();
		}
		float screenW = d.Width > 0 ? (float)d.Width : 1280.0f;
		float screenH = d.Height > 0 ? (float)d.Height : 720.0f;

		// We are inside the game's already-active render scene (this runs from the
		// EndScene hook, before the original EndScene presents). Draw directly to the
		// current render target and restore device state afterwards. No nested
		// BeginScene/EndScene or render-target juggling is needed here.
		IDirect3DStateBlock9* state = nullptr;
		if (FAILED(pDevice->CreateStateBlock(D3DSBT_ALL, &state)))
			state = nullptr;
		if (state)
			state->Capture();

		IDirect3DSurface9* prevRt = nullptr;
		if (SUCCEEDED(pDevice->GetRenderTarget(0, &prevRt)) && prevRt)
		{
			DrawToasts(screenW, screenH);
			if (s_showDebug)
				DrawDebugPanel(screenW, screenH);
			prevRt->Release();
			prevRt = nullptr;
		}

		if (state)
		{
			state->Apply();
			state->Release();
		}
	}

} // namespace Achievements
