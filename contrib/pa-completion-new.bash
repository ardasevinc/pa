# requires bash-completion >= v2.12.0, preferably >= v2.17.0

_comp_pa_entries() {
	pushd "$PA_DIR/passwords" &>/dev/null || return
	_comp_compgen_split -l "$(find . -type f -name \*.age | sed 's/..//;s/\.age$//')"
	popd &>/dev/null || return
}

_comp_pa_categories() {
	_comp_compgen -C "$PA_DIR/passwords" filedir -df
	local i
	for i in "${!COMPREPLY[@]}"; do
		if [[ ${COMPREPLY[i]} == .git/ ]]; then
			unset 'COMPREPLY[i]'
			break
		fi
	done
}

_comp_cmd_pa() {
	local words cword
	_comp_initialize -- "$@" || return

	if [[ $cword -eq 1 ]]; then
		_comp_compgen_split "add del edit git list move show"
		return
	fi

	local PA_DIR=${PA_DIR:-$HOME/.local/share/pa}
	[[ -d $PA_DIR/passwords ]] || return

	case ${words[1]} in
	[al]*) [[ $cword -eq 2 ]] && _comp_pa_categories ;;
	[des]*) [[ $cword -eq 2 ]] && _comp_pa_entries ;;
	m*)
		if [[ $cword -eq 2 ]]; then
			_comp_pa_entries
		elif [[ $cword -eq 3 ]]; then
			_comp_pa_categories
		fi
		;;
	g*)
		pushd "$PA_DIR/passwords" &>/dev/null || return
		if [[ ${words[1]} != git ]]; then
			COMP_LINE=${words[0]}\ git${COMP_LINE#*"${words[0]} ${words[1]}"}
			((COMP_POINT += 3 - ${#words[1]}))
			COMP_WORDS[1]=git
		fi
		_comp_command_offset 1
		popd &>/dev/null || return
		;;
	esac
}

complete -F _comp_cmd_pa pa
