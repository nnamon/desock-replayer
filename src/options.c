// Adapted from Preeny (Yan Shoshitaishvili) by amon
// This code is GPLed by Yan Shoshitaishvili

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define STR_REPLAY_SOURCE_DIR "REPLAY_SOURCE_DIR"
#define STR_REPLAY_FUZZ_TARGET_FILE "REPLAY_FUZZ_TARGET_FILE"
#define STR_REPLAY_FUZZ_INDEX "REPLAY_FUZZ_INDEX"
#define STR_REPLAY_EXIT_ON_INJECTION "REPLAY_EXIT_ON_INJECTION"


char * replay_source_dir = "./packets/";
int replay_fuzz_index = -1; // Do not fuzz anything, just replay if -1
char * replay_fuzz_target_file = "./working_packet.data";
int replay_exit_on_injection = 0;

__attribute__((constructor)) void replay_options_init()
{
    if (getenv(STR_REPLAY_SOURCE_DIR)) {
        replay_source_dir = getenv(STR_REPLAY_SOURCE_DIR);
    }

    if (getenv(STR_REPLAY_FUZZ_INDEX)) {
        replay_fuzz_index = atoi(getenv(STR_REPLAY_FUZZ_INDEX));
    }

    if (getenv(STR_REPLAY_FUZZ_TARGET_FILE)) {
        replay_fuzz_target_file = getenv(STR_REPLAY_FUZZ_TARGET_FILE);
    }

    if (getenv(STR_REPLAY_EXIT_ON_INJECTION)) {
        replay_exit_on_injection = 1;
    }
}
