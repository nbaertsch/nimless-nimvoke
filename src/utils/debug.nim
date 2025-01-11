template std_debug_print*(args: varargs[untyped]) =
    when defined(std_debug):
        echo args