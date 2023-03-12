/**
 * Helper functions for debug printing and such
*/

#include <stdio.h>

#ifndef HTTP_DEBUG_H
#define HTTP_DEBUG_H

#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__);
#else
#define DEBUG_PRINT(...) do {} while (0)
#endif

#define PRINT_ERROR() fprintf(stderr, "Error at line %d in file %s\n", __LINE__, __FILE__)

#endif
