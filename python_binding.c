#pragma once

#include "main.h"

#define PY_SSIZE_T_CLEAN
#include <Python.h>


static PyObject * wgs_gitstatus(PyObject *self, PyObject *args) {
    const char *path;

    if (!PyArg_ParseTuple(args, "s", &path))
        return NULL;

    GitStatus gs = gitstatus(path);
    PyObject *tuple = Py_BuildValue("iss", gs.git_found, gs.branch, gs.status);

    reset_memory();

    return tuple;
};


static PyMethodDef wgs_methods[] = {
    {"gitstatus", wgs_gitstatus, METH_VARARGS, "Get the git status of given path"},
    {NULL, NULL, 0, NULL}
};


static struct PyModuleDef wgs_module = {
    PyModuleDef_HEAD_INIT,
    "wgs",  // name of mod, 'import wgs'
    "Docs for wgs module.",
    -1,
    wgs_methods
};


PyMODINIT_FUNC PyInit_wgs() {
    setup_memory();
    return PyModule_Create(&wgs_module);
};
