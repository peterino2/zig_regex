# Zig Regex

A fairly quick regex implementation done a while back for learning purposes, Imma just clean it up and put it out there.
This one is largely implemented with tagged unions and recursive descent rather than a state machine or a 
byte gobbler so it shows you actually can write zig programs in a fairly functional manner. 

In fact it's pretty damn nice for it.

You can test the library with 

```zig
zig test gregex.zig
```

Usecases can be found in the .zig file itself,

but here's a simple usecase.

```zig
    var test_restr = "name: *(.*)\\((.*)\\)$";

    var find = try re_find_once(test_restr, "date: 2077-06-24 name: adam jensen (occupation: killa)\n", alloc);
    defer find.deinit(); // find has an arraylist of regex objects, this should be de-initialized when out of scope.

    print("{s}\n", .{ find.text }); // This will print out the entire string
    
    // the result supports groups
    print("find.groups.items[1] = '{s}':\n", .{find.groups.items[0].text});
    print("find.groups.items[2] = '{s}':\n", .{find.groups.items[0].text});
```

in terms of sequences, a few of the most commonly supported sequences are supported.

- `*, +, ?` : capture mode operators, respectively; zero or more, one or more, zero or one
- `()` : create a match group (does not support nesting)
- `[]`: or match group (match any union of elements within)
- `a-z`: sequence range match
- predefined semantic groups:
    - `\s` : (capital version is inverted)
    - `\w` : word
- `!`: Single term negation negates matches that are a single term. does not work on `()` groups or. but will work on or-groups.
    - negative look-ahead is not supported.

Note: this is the first thing I've ever actually written in zig so there's a few growing pains in visible in the code.
