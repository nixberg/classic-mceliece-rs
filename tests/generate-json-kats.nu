#!/usr/bin/env nu

def load-rsp [input_file: string] {
    open $input_file |
    split row "\n\n" |
    each {
        lines |
        parse "{key}={value}" |
        update key   { get key   | str trim | str downcase } |
        update value { get value | str trim | str downcase } |
        pivot --header-row |
        update count { get count | str to-int }
    }
}

load-rsp "kats.rsp" |
    merge { open "kats-patch.json" } |
    to json --pretty 4 |
    save "kats.json" --raw
