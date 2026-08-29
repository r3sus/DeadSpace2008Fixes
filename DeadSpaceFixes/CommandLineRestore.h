#pragma once

namespace CommandLineRestore {
	// Restores the game's cut command-line handling: the engine's boot path
	// (sub_414A60) calls sub_401050(&Str) with a static/empty string, so real
	// argv and the cmd.txt file are never parsed. We replace that call site so
	// the engine's own argv+cmd.txt wrapper (sub_4012C0) runs instead.
	void Initialise();
}
