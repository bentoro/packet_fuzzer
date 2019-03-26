#include "logging.h"

/* =====================================================================================
 *
 *       function: print_time()
 *
 *         return: void
 *
 *       Parameters:
 *
 *       Author: Benedict Lo
 *
 *       Notes:
 *              print the current time
 *
 * ====================================================================================*/
void print_time(){
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    printf("[%d-%d-%d %d:%d:%d] ", tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec);
}
