/*
   Copyright (c) 2007-2013. The YARA Authors. All Rights Reserved.

   Redistribution and use in source and binary forms, with or without modification,
   are permitted provided that the following conditions are met:

   1. Redistributions of source code must retain the above copyright notice, this
   list of conditions and the following disclaimer.

   2. Redistributions in binary form must reproduce the above copyright notice,
   this list of conditions and the following disclaimer in the documentation and/or
   other materials provided with the distribution.

   3. Neither the name of the copyright holder nor the names of its contributors
   may be used to endorse or promote products derived from this software without
   specific prior written permission.

   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
   ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
   DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR
   ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
   (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
   LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
   ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
   SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#if !defined(_WIN32) && !defined(__CYGWIN__)

#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <inttypes.h>

#else

#include <windows.h>

#define PRIx64 "I64x"
#define PRId64 "I64d"

#endif

#include <time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <yara.h>

#include "args.h"
#include "./common.h"
#include "./threading.h"


#define ERROR_COULD_NOT_CREATE_THREAD  100

#ifndef MAX_PATH
#define MAX_PATH 256
#endif

#ifndef min
#define min(x, y)  ((x < y) ? (x) : (y))
#endif

#ifdef _MSC_VER
#define snprintf _snprintf
#define strdup _strdup
#endif

#define MAX_QUEUED_FILES 64


typedef struct _MODULE_DATA
{
    const char* module_name;
    YR_MAPPED_FILE mapped_file;
    struct _MODULE_DATA* next;

} MODULE_DATA;


typedef struct _CALLBACK_ARGS
{
    const char* file_path;
    int current_count;

} CALLBACK_ARGS;


typedef struct _THREAD_ARGS
{
    YR_SCANNER*       scanner;
    CALLBACK_ARGS     callback_args;
    time_t            start_time;
    int               current_count;

} THREAD_ARGS;


typedef struct _QUEUED_FILE
{
    char* path;

} QUEUED_FILE;


typedef struct COMPILER_RESULTS
{
    int errors;
    int warnings;

} COMPILER_RESULTS;

YR_SCANNER *scanner;

#define MAX_ARGS_TAG            32
#define MAX_ARGS_IDENTIFIER     32
#define MAX_ARGS_EXT_VAR        32
#define MAX_ARGS_MODULE_DATA    32

static char* ext_vars[MAX_ARGS_EXT_VAR + 1];
static char* modules_data[MAX_ARGS_EXT_VAR + 1];

static bool show_module_data = false;
static bool fast_scan = false;
static int timeout = 1000000;
static int stack_size = DEFAULT_STACK_SIZE;
static int max_strings_per_rule = DEFAULT_MAX_STRINGS_PER_RULE;


#define USAGE_STRING \
    "Usage: yara [OPTION]... [NAMESPACE:]RULES_FILE... FILE | DIR | PID"


// file_queue is size-limited queue stored as a circular array, files are
// removed from queue_head position and new files are added at queue_tail
// position. The array has room for one extra element to avoid queue_head
// being equal to queue_tail in a full queue. The only situation where
// queue_head == queue_tail is when queue is empty.

QUEUED_FILE file_queue[MAX_QUEUED_FILES + 1];

int queue_head;
int queue_tail;

SEMAPHORE used_slots;
SEMAPHORE unused_slots;

MODULE_DATA* modules_data_list = NULL;

static void print_error(
                        int error)
{
    switch (error)
    {
    case ERROR_SUCCESS:
        break;
    case ERROR_COULD_NOT_ATTACH_TO_PROCESS:
        fprintf(stderr, "can not attach to process (try running as root)\n");
        break;
    case ERROR_INSUFFICIENT_MEMORY:
        fprintf(stderr, "not enough memory\n");
        break;
    case ERROR_SCAN_TIMEOUT:
        fprintf(stderr, "scanning timed out\n");
        break;
    case ERROR_COULD_NOT_OPEN_FILE:
        fprintf(stderr, "could not open file\n");
        break;
    case ERROR_UNSUPPORTED_FILE_VERSION:
        fprintf(stderr, "rules were compiled with a different version of YARA\n");
        break;
    case ERROR_CORRUPT_FILE:
        fprintf(stderr, "corrupt compiled rules file.\n");
        break;
    case ERROR_EXEC_STACK_OVERFLOW:
        fprintf(stderr, "stack overflow while evaluating condition "
                "(see --stack-size argument) \n");
        break;
    case ERROR_INVALID_EXTERNAL_VARIABLE_TYPE:
        fprintf(stderr, "invalid type for external variable\n");
        break;
    case ERROR_TOO_MANY_MATCHES:
        fprintf(stderr, "too many matches\n");
        break;
    default:
        fprintf(stderr, "internal error: %d\n", error);
        break;
    }
}

static int callback(
                    int message,
                    void* message_data,
                    void* user_data)
{
    YR_MODULE_IMPORT* mi;
    YR_OBJECT* object;
    MODULE_DATA* module_data;

    switch(message)
    {
    case CALLBACK_MSG_RULE_MATCHING:
        *((char **)user_data) = (char *)((YR_RULE*) message_data)->identifier;
        return CALLBACK_ABORT;
    case CALLBACK_MSG_RULE_NOT_MATCHING:
        return CALLBACK_CONTINUE;

    case CALLBACK_MSG_IMPORT_MODULE:

        mi = (YR_MODULE_IMPORT*) message_data;
        module_data = modules_data_list;

        while (module_data != NULL)
        {
            if (strcmp(module_data->module_name, mi->module_name) == 0)
            {
                mi->module_data = (void*) module_data->mapped_file.data;
                mi->module_data_size = module_data->mapped_file.size;
                break;
            }

            module_data = module_data->next;
        }

        return CALLBACK_CONTINUE;

    case CALLBACK_MSG_MODULE_IMPORTED:

        if (show_module_data)
        {
            object = (YR_OBJECT*) message_data;

            yr_object_print_data(object, 0, 1);
            printf("\n");

        }

        return CALLBACK_CONTINUE;
    }

    return CALLBACK_ERROR;
}

static int define_external_variables(
                                     YR_RULES* rules,
                                     YR_COMPILER* compiler)
{
    int result = ERROR_SUCCESS;

    for (int i = 0; ext_vars[i] != NULL; i++)
    {
        char* equal_sign = strchr(ext_vars[i], '=');

        if (!equal_sign)
        {
            fprintf(stderr, "error: wrong syntax for `-d` option.\n");
            return ERROR_SUCCESS;
        }

        // Replace the equal sign with null character to split the external
        // variable definition (i.e: myvar=somevalue) in two strings: identifier
        // and value.

        *equal_sign = '\0';

        char* identifier = ext_vars[i];
        char* value = equal_sign + 1;

        if (is_float(value))
        {
            if (rules != NULL)
                result = yr_rules_define_float_variable(
                                                        rules,
                                                        identifier,
                                                        atof(value));

            if (compiler != NULL)
                result = yr_compiler_define_float_variable(
                                                           compiler,
                                                           identifier,
                                                           atof(value));
        }
        else if (is_integer(value))
        {
            if (rules != NULL)
                result = yr_rules_define_integer_variable(
                                                          rules,
                                                          identifier,
                                                          atoi(value));

            if (compiler != NULL)
                result = yr_compiler_define_integer_variable(
                                                             compiler,
                                                             identifier,
                                                             atoi(value));
        }
        else if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0)
        {
            if (rules != NULL)
                result = yr_rules_define_boolean_variable(
                                                          rules,
                                                          identifier,
                                                          strcmp(value, "true") == 0);

            if (compiler != NULL)
                result = yr_compiler_define_boolean_variable(
                                                             compiler,
                                                             identifier,
                                                             strcmp(value, "true") == 0);
        }
        else
        {
            if (rules != NULL)
                result = yr_rules_define_string_variable(
                                                         rules,
                                                         identifier,
                                                         value);

            if (compiler != NULL)
                result = yr_compiler_define_string_variable(
                                                            compiler,
                                                            identifier,
                                                            value);
        }
    }

    return result;
}


static int load_modules_data()
{
    for (int i = 0; modules_data[i] != NULL; i++)
    {
        char* equal_sign = strchr(modules_data[i], '=');

        if (!equal_sign)
        {
            fprintf(stderr, "error: wrong syntax for `-x` option.\n");
            return false;
        }

        *equal_sign = '\0';

        MODULE_DATA* module_data = (MODULE_DATA*) malloc(sizeof(MODULE_DATA));

        if (module_data != NULL)
        {
            module_data->module_name = modules_data[i];

            int result = yr_filemap_map(equal_sign + 1, &module_data->mapped_file);

            if (result != ERROR_SUCCESS)
            {
                free(module_data);
                fprintf(stderr, "error: could not open file \"%s\".\n", equal_sign + 1);
                return false;
            }

            module_data->next = modules_data_list;
            modules_data_list = module_data;
        }
    }

    return true;
}


static void unload_modules_data()
{
    MODULE_DATA* module_data = modules_data_list;

    while(module_data != NULL)
    {
        MODULE_DATA* next_module_data = module_data->next;

        yr_filemap_unmap(&module_data->mapped_file);
        free(module_data);

        module_data = next_module_data;
    }

    modules_data_list = NULL;
}

int
yara_av_init(char *pattern_file)
{
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;

    int flags = 0;
    int result ;

    if (!load_modules_data())
        exit_with_code(EXIT_FAILURE);

    result = yr_initialize();

    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "error: initialization error (%d)\n", result);
        exit_with_code(EXIT_FAILURE);
    }

    yr_set_configuration(YR_CONFIG_STACK_SIZE, &stack_size);
    yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, &max_strings_per_rule);

    // Try to load the rules file as a binary file containing
    // compiled rules first

    result = yr_rules_load(pattern_file, &rules);

    // Accepted result are ERROR_SUCCESS or ERROR_INVALID_FILE
    // if we are passing the rules in source form, if result is
    // different from those exit with error.

    if (result != ERROR_SUCCESS) 
    {
        print_error(result);
        exit_with_code(EXIT_FAILURE);
    }

    result = define_external_variables(rules, NULL);

    if (result != ERROR_SUCCESS)
    {
        print_error(result);
        exit_with_code(EXIT_FAILURE);
    }


    if (fast_scan) {
        flags |= SCAN_FLAGS_FAST_MODE;
    }


    result = yr_scanner_create(rules, &scanner);

    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "error: %d\n", result);
        exit_with_code(EXIT_FAILURE);
    }

    yr_scanner_set_callback(scanner, callback, NULL);
    yr_scanner_set_flags(scanner, flags);
    yr_scanner_set_timeout(scanner, timeout);
    return ERROR_SUCCESS;
_exit:

#ifdef PROFILING_ENABLED
    if (rules != NULL)
        yr_rules_print_profiling_info(rules);
#endif

    unload_modules_data();

    if (scanner != NULL)
        yr_scanner_destroy(scanner);

    if (compiler != NULL)
        yr_compiler_destroy(compiler);

    if (rules != NULL)
        yr_rules_destroy(rules);

    yr_finalize();

    return result;
}

int
yara_av_scan(char *file, char **virus_info)
{
    yr_scanner_set_callback(scanner, callback, virus_info);
    return yr_scanner_scan_file(scanner, file);
}

#if 0
int yara_av(char *pattern_file, char *file)
{
    YR_COMPILER* compiler = NULL;
    YR_RULES* rules = NULL;
    YR_SCANNER* scanner = NULL;

    int flags = 0;
    int result ;

    if (!load_modules_data())
        exit_with_code(EXIT_FAILURE);

    result = yr_initialize();

    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "error: initialization error (%d)\n", result);
        exit_with_code(EXIT_FAILURE);
    }

    yr_set_configuration(YR_CONFIG_STACK_SIZE, &stack_size);
    yr_set_configuration(YR_CONFIG_MAX_STRINGS_PER_RULE, &max_strings_per_rule);

    // Try to load the rules file as a binary file containing
    // compiled rules first

    result = yr_rules_load(pattern_file, &rules);

    // Accepted result are ERROR_SUCCESS or ERROR_INVALID_FILE
    // if we are passing the rules in source form, if result is
    // different from those exit with error.

    if (result != ERROR_SUCCESS) 
    {
        print_error(result);
        exit_with_code(EXIT_FAILURE);
    }

    result = define_external_variables(rules, NULL);

    if (result != ERROR_SUCCESS)
    {
        print_error(result);
        exit_with_code(EXIT_FAILURE);
    }


    if (fast_scan) {
        flags |= SCAN_FLAGS_FAST_MODE;
    }


    result = yr_scanner_create(rules, &scanner);

    if (result != ERROR_SUCCESS)
    {
        fprintf(stderr, "error: %d\n", result);
        exit_with_code(EXIT_FAILURE);
    }

    yr_scanner_set_callback(scanner, callback, NULL);
    yr_scanner_set_flags(scanner, flags);
    yr_scanner_set_timeout(scanner, timeout);

    result = yr_scanner_scan_file(scanner, file);


    result = EXIT_SUCCESS;

_exit:

#ifdef PROFILING_ENABLED
    if (rules != NULL)
        yr_rules_print_profiling_info(rules);
#endif

    unload_modules_data();

    if (scanner != NULL)
        yr_scanner_destroy(scanner);

    if (compiler != NULL)
        yr_compiler_destroy(compiler);

    if (rules != NULL)
        yr_rules_destroy(rules);

    yr_finalize();

    return result;
}
#endif
