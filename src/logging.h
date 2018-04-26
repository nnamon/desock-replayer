// Adapted from Preeny (Yan Shoshitaishvili) by amon
#pragma once

extern int preeny_debug_on;
extern int preeny_info_on;
extern int preeny_error_on;
extern int preeny_investigate_on;

void preeny_debug(char *, ...);
void preeny_info(char *, ...);
void preeny_error(char *, ...);
void preeny_investigate(char *, ...);
