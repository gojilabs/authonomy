#!/bin/bash

HOOK_NAMES="applypatch-msg pre-applypatch post-applypatch pre-commit prepare-commit-msg commit-msg post-commit pre-rebase post-checkout post-merge pre-receive update post-receive post-update pre-auto-gc"

HOOK_DIR=$(git rev-parse --show-toplevel)/.git/hooks

for hook in $HOOK_NAMES; do
    # Only for hooks that exist in 'script' directory (now it's 'pre-commit' only)
    if [ -f $(dirname $0)/$hook ]; then
        # If the hook already exists in 'hooks' directory, is executable, and is not a symlink
        if [ ! -h $HOOK_DIR/$hook -a -x $HOOK_DIR/$hook ]; then
            mv $HOOK_DIR/$hook $HOOK_DIR/$hook.local
        fi

        # Create the symlink, overwriting the file if it exists
        ln -s -f ../../script/git-hook-wrapper.sh $HOOK_DIR/$hook
    fi
done
