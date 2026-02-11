function __fish_pa_using_command
    set -l cmd (commandline -xpc)
    test (count $cmd) -gt 1; and string match -q -r $argv[1] $cmd[2]
end

function __fish_pa_categories
    pushd $PA_DIR/passwords >/dev/null
    and __fish_complete_directories (commandline -ct) ''
    popd >/dev/null
end

function __fish_pa_entries
    pushd $PA_DIR/passwords >/dev/null
    and path change-extension '' (string sub -s 3 (find . -type f -name \*.age))
    popd >/dev/null
end

function __fish_pa_move_complete
    set -l cmd_count (count (commandline -xpc))
    if test $cmd_count -eq 2
        __fish_pa_entries
    else if test $cmd_count -eq 3
        __fish_pa_categories
    end
end

function __fish_pa_git_complete
    set -l git_cmd (commandline -xpc) (commandline -ct)
    set -e git_cmd[1 2]
    pushd $PA_DIR/passwords >/dev/null
    and complete -C"git $git_cmd"
    popd >/dev/null
end

complete -c pa -f
complete -c pa -n __fish_is_first_token -a add -d 'Add a password entry'
complete -c pa -n __fish_is_first_token -a delete -d 'Delete a password entry'
complete -c pa -n __fish_is_first_token -a edit -d "Edit a password entry with $EDITOR"
complete -c pa -n __fish_is_first_token -a git -d 'Run git command in the password dir'
complete -c pa -n __fish_is_first_token -a list -d 'List all entries in a category'
complete -c pa -n __fish_is_first_token -a move -d 'Rename a password entry'
complete -c pa -n __fish_is_first_token -a show -d 'Show password for an entry'

set -q PA_DIR || set PA_DIR $HOME/.local/share/pa

complete -c pa -n '__fish_pa_using_command ^[al]' -a '(__fish_is_nth_token 2; and __fish_pa_categories)'
complete -c pa -n '__fish_pa_using_command ^[des]' -a '(__fish_is_nth_token 2; and __fish_pa_entries)'
complete -c pa -n '__fish_pa_using_command ^m' -a '(__fish_pa_move_complete)'
complete -c pa -n '__fish_pa_using_command ^g' -a '(__fish_pa_git_complete)'
