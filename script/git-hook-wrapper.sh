#!/bin/bash

# Call user local hook if it exists
if [ -x $0.local ]; then
    $0.local "$@" || exit $?
fi

# Assuming the caller hook is symlink from 'hooks' directory to this file
if [[ "$OSTYPE" == "darwin"* ]]; then
    SCRIPT_DIR=$(dirname "$(greadlink -f $0)")
else
    SCRIPT_DIR=$(dirname "$(readlink -f $0)")
fi

# Call hook from 'script' directory
if [ -x $SCRIPT_DIR/"$(basename $0)" ]; then
    $SCRIPT_DIR/"$(basename $0)" "$@" || exit $?
fi
