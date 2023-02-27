/**
 * Helper functions for debug printing and such
*/

#include <stdio.h>

#ifndef HTTP_DEBUG_H
#define HTTP_DEBUG_H

#ifdef DEBUG
#define DEBUG_PRINT(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINT(...) do {} while (0)
#endif



#endif
