function count_char(text, character, copy) {
    copy = text
    return gsub(character, "", copy)
}

function finish_function(name, lines) {
    name = function_name[function_count]
    lines = function_code_lines[function_count]
    if (lines > 70) {
        printf "%s:%d: function %s is %d lines of code; maximum is 70\n", \
            FILENAME, function_start[function_count], name, lines
        failed = 1
    }
    delete function_name[function_count]
    delete function_start[function_count]
    delete function_depth[function_count]
    delete function_code_lines[function_count]
    function_count--
}

{
    is_code = ($0 !~ /^[[:space:]]*(\/\/|$)/)

    if (is_code) {
        code_lines++
        for (i = 1; i <= function_count; i++) {
            function_code_lines[i]++
        }
    }

    if (length($0) > 99) {
        printf "%s:%d: line is %d characters; maximum is 99\n", \
            FILENAME, FNR, length($0)
        failed = 1
    }

    if (index($0, "\t") != 0) {
        printf "%s:%d: tab character is not permitted\n", FILENAME, FNR
        failed = 1
    }

    if (!pending && match($0, /(^|[[:space:]])(pub[[:space:]]+)?(inline[[:space:]]+)?fn[[:space:]]+[A-Za-z0-9_]+/)) {
        pending_name = $0
        sub(/^.*fn[[:space:]]+/, "", pending_name)
        sub(/\(.*/, "", pending_name)
        pending_start = FNR
        pending = 1
    }

    opens = count_char($0, "{")
    closes = count_char($0, "}")
    if (pending && opens > 0) {
        function_count++
        function_name[function_count] = pending_name
        function_start[function_count] = pending_start
        function_depth[function_count] = brace_depth + 1
        function_code_lines[function_count] = is_code ? 1 : 0
        pending = 0
    }

    brace_depth += opens - closes
    while (function_count > 0 && brace_depth < function_depth[function_count]) {
        finish_function()
    }
}

END {
    if (code_lines > 1408) {
        printf "%s: %d lines of code; maximum is 1408 (comments and blanks excluded)\n", \
            FILENAME, code_lines
        failed = 1
    }
    if (failed) exit 1
}
