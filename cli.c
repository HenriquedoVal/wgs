#pragma once

#include <stdio.h>

#include "main.h"


int main(int argc, char **argv) {
    const char *program_name = argv[0];

    if (argc <= 1) {
        fprintf(stdout, "ERROR: No input path is provided\n");
        return 1;
    }

    setup();

    for (int i = 1; i < argc; i++) {
        const char *path = argv[i];
        GitStatus gs = gitstatus(path);
        printf(
            "%s\n\tFound: %s\n\tBranch: %s\n\tStatus: %s\n",
            path,
            gs.git_found ? "True" : "False",
            gs.branch,
            gs.status
        );
        reset_memory();
    }

    return 0;
}
