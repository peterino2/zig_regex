const std = @import("std");
const expect = std.testing.expect;
const dir: fs.Dir = fs.cwd();
const ArrayList = std.ArrayList;
const mem = std.mem;

// Finds first math, returns a char slice, cleans up after itself
pub fn re_findstr_once(re_str: []const u8, src: []const u8, allocator: *std.mem.Allocator) ![]const u8 {
    var compiled = try ReParser.compile(re_str, allocator);
    defer compiled.deinit();
    var rv = compiled.findstr_once(src);
    return rv;
}

pub const ReMatch = struct {
    text: []const u8,
    is_match: bool = true,
    groups: ArrayList(ReMatchGroup),
    alloc: *std.mem.Allocator,

    pub fn deinit(self: *ReMatch) void {
        self.groups.deinit();
    }

    pub fn init(alloc: *std.mem.Allocator) !ReMatch {
        return ReMatch{
            .text = "",
            .groups = ArrayList(ReMatchGroup).init(alloc),
            .alloc = alloc,
        };
    }

    pub fn push_group(self: *ReMatch, group: ReMatchGroup) !void {
        try self.groups.append(group);
    }
};

// Remember to invoke the ReMatch.deinit() function
pub fn re_find_once(re_str: []const u8, src: []const u8, allocator: *std.mem.Allocator) !ReMatch {
    var compiled = try ReParser.compile(re_str, allocator);
    defer compiled.deinit();
    return compiled.find_once(src, allocator);
}

// Use case examples
test "usecase_simple" {
    const should_print: bool = true;
    const print = if (should_print) std.debug.print else test_noprint;
    var alloc = std.testing.allocator;

    var test_restr = "name: *(.*)\\((.*)\\)$";

    var find = try re_find_once(test_restr, "date: 2077-06-24 name: adam jensen (occupation: killa)\n", alloc);
    defer find.deinit(); // find has an arraylist of regex objects, this should be de-initialized when out of scope.

    print("find = '{s}{s}':\n", .{ find.text[0 .. find.text.len - 1], "\n" }); // the whole find string (this includes the end of line string)
    print("find.groups.items[1] = '{s}':\n", .{find.groups.items[0].text});
    print("find.groups.items[2] = '{s}':\n", .{find.groups.items[0].text});
    try expect(find.groups.items[0].text.len == "adam jensen ".len);
    std.debug.assert(std.mem.eql(u8, "adam jensen ", find.groups.items[0].text));
    std.debug.assert(std.mem.eql(u8, "occupation: killa", find.groups.items[1].text));
}

const GRegexRepeatMode = enum {
    zeroOrMore,
    oneOrMore,
    zeroOrOne,
    nTimes, // not implemented
};

const GRegexObject = struct {
    invert: bool = false,
    inner: union(enum) {
        single: []const u8,
        matchGroup: ArrayList(GRegexObject),
        range: struct {
            min: u8,
            max: u8,
        },
        orgroup: ArrayList(GRegexObject),
        repeatingGroup: struct {
            group: ArrayList(GRegexObject),
            repeat_mode: GRegexRepeatMode,
            repeat_count: u32,
        },
    },

    pub fn deinit(self: *GRegexObject) void {
        switch (self.inner) {
            .orgroup, .matchGroup => |*inner| {
                for (inner.items) |*regex_obj| {
                    regex_obj.deinit();
                }
                inner.deinit();
            },
            .repeatingGroup => |*inner| {
                for (inner.group.items) |*regex_obj| {
                    regex_obj.deinit();
                }
                inner.group.deinit();
            },
            else => {},
        }
    }

    pub fn make_match_group(allocator: *std.mem.Allocator) ReCompileObjectError!GRegexObject {
        var rv: GRegexObject = .{ .inner = .{ .matchGroup = ArrayList(GRegexObject).init(allocator) } };
        return rv;
    }

    pub fn make_line_end(allocator: *std.mem.Allocator) ReCompileObjectError!GRegexObject {
        var regex_obj = GRegexObject.make_orgroup(allocator);
        var ored_groups = [_]GRegexObject{
            .{ .inner = .{ .single = "\n" } },
            .{ .inner = .{ .matchGroup = ArrayList(GRegexObject).init(allocator) } },
        };
        try ored_groups[1].inner.matchGroup.append(GRegexObject{ .inner = .{ .single = "\r" } });
        try ored_groups[1].inner.matchGroup.append(GRegexObject{ .inner = .{ .single = "\n" } });

        for (ored_groups) |obj, i| {
            try regex_obj.inner.orgroup.append(obj);
        }

        return regex_obj;
    }

    pub fn make_alphanumeric(allocator: *std.mem.Allocator) ReCompileObjectError!GRegexObject {
        var regex_obj = GRegexObject.make_orgroup(allocator);
        var ored_groups = [_]GRegexObject{
            .{ .inner = .{ .range = .{ .min = 'a', .max = 'z' } } },
            .{ .inner = .{ .range = .{ .min = 'A', .max = 'Z' } } },
            .{ .inner = .{ .range = .{ .min = '0', .max = '9' } } },
            .{ .inner = .{ .single = "_" } },
        };

        for (ored_groups) |obj, i| {
            try regex_obj.inner.orgroup.append(obj);
        }

        return regex_obj;
    }

    pub fn make_digits(allocator: *std.mem.Allocator) ReCompileObjectError!GRegexObject {
        var regex_obj = GRegexObject.make_orgroup(allocator);
        var ored_groups = [_]GRegexObject{
            .{ .inner = .{ .range = .{ .min = '0', .max = '9' } } },
        };

        for (ored_groups) |obj, i| {
            try regex_obj.inner.orgroup.append(obj);
        }

        return regex_obj;
    }

    pub fn make_repeating_group(repeat_mode_str: []const u8, allocator: *std.mem.Allocator) !GRegexObject {
        var regex_obj = GRegexObject{ .inner = .{ .repeatingGroup = .{
            .group = ArrayList(GRegexObject).init(allocator),
            .repeat_mode = switch (repeat_mode_str[0]) {
                '*' => GRegexRepeatMode.zeroOrMore,
                '+' => GRegexRepeatMode.oneOrMore,
                '?' => GRegexRepeatMode.zeroOrOne,
                '{' => GRegexRepeatMode.nTimes,
                else => return ReCompileError.UnexpectedToken,
            },
            .repeat_count = 0,
        } } };

        return regex_obj;
    }

    pub fn make_whitespace(allocator: *std.mem.Allocator) ReCompileObjectError!GRegexObject {
        var regex_obj = GRegexObject.make_orgroup(allocator);
        var ored_groups = [_]GRegexObject{
            .{ .inner = .{ .single = "\t" } },
            .{ .inner = .{ .single = "\n" } },
            .{ .inner = .{ .single = "\r" } },
            .{ .inner = .{ .single = " " } },
        };
        for (ored_groups) |obj, i| {
            try regex_obj.inner.orgroup.append(obj);
        }
        return regex_obj;
    }

    pub fn make_orgroup(allocator: *std.mem.Allocator) GRegexObject {
        var push_obj: GRegexObject = .{ .inner = .{ .orgroup = ArrayList(GRegexObject).init(allocator) } };
        return push_obj;
    }

    const MatchObject = struct {
        data: []const u8,
        is_match: bool = false,
        backstop_offset: usize = 0,
    };

    pub fn equals(self: GRegexObject, other: GRegexObject) bool {
        return false;
    }

    pub fn is_backstop(self: GRegexObject, for_obj: *const GRegexObject) bool {
        // std.debug.print("checking backstop:", .{});
        // self.pretty_print(0, std.debug.print);
        switch (self.inner) {
            .range => return true,
            .single => return true,
            .matchGroup => |*match_group| {
                if (match_group.items.len > 0) {
                    return match_group.items[0].is_backstop(for_obj);
                }
                return true;
            },
            .orgroup => return true,
            .repeatingGroup => |*group| {
                if (group.repeat_mode == GRegexRepeatMode.zeroOrOne or group.repeat_mode == GRegexRepeatMode.zeroOrMore) {
                    switch (for_obj.inner) {
                        .repeatingGroup => |*for_group| {
                            if (group.group.items.len != for_group.group.items.len) {
                                return true;
                            }
                            var i: u32 = 0;
                            while (i < group.group.items.len) : (i += 1) {
                                var left = group.group.items[i];
                                var right = for_group.group.items[i];
                                if (!left.equals(right)) {
                                    return true;
                                }
                            }
                        },
                        else => return false,
                    }
                    return false;
                }
                return true;
            },
        }
    }

    pub fn match(self: *const GRegexObject, src: []const u8, next_objects: []const GRegexObject) ReSearchError!MatchObject {
        const no_match = MatchObject{ .data = "", .is_match = false };
        // self.pretty_print(0, std.debug.print);

        switch (self.*.inner) {
            .range => |range| {
                var good_match = MatchObject{ .data = src[0..1], .is_match = true };
                var check: bool = (src[0] >= range.min and src[0] <= range.max);

                if (self.invert) {
                    check = !check;
                }

                return if (check) good_match else no_match;
            },
            .single => |single| {
                var good_match = MatchObject{ .data = src[0..single.len], .is_match = true };
                var check: bool = std.mem.startsWith(u8, src, single);
                if (self.invert) check = !check;
                return if (check) good_match else no_match;
            },
            .orgroup => |orgroup| {
                for (orgroup.items) |regex_obj, i| {
                    var next_objects_start: usize = 0;
                    if (next_objects.len > 0) next_objects_start = 1;
                    var match_obj = try regex_obj.match(src, next_objects[next_objects_start..]);
                    if (self.invert and !match_obj.is_match) {
                        return match_obj;
                    } else if (match_obj.is_match) {
                        return match_obj;
                    }
                }
            },
            .matchGroup => |match_group| {
                var match_obj = MatchObject{ .data = "", .is_match = false };
                var pos: usize = 0;
                var matches: bool = true;

                for (match_group.items) |regex_obj, index| {
                    var start_index: usize = if (match_group.items.len > 1) 1 else 0;
                    // check if we're the final object. if it's the back last object then use the higher scope
                    // next_objects instead of the next ones in this specific regex_obj
                    var inner_next_obj = if (index < (match_group.items.len - 1)) match_group.items[start_index..] else next_objects;

                    var match_inner = try regex_obj.match(src[pos..], inner_next_obj);
                    if (match_inner.is_match) {
                        pos += match_inner.data.len;
                    } else {
                        matches = false;
                    }
                }

                if (matches) {
                    match_obj.data = src[0..pos];
                    match_obj.is_match = true;
                }

                // std.debug.print("match group = '{s}' src= {s}\n", .{ match_obj.data, src });

                return match_obj;
            },
            .repeatingGroup => |repeating_group| {
                var match_obj = MatchObject{ .data = "", .is_match = false };
                var pos: usize = 0;
                var backstop_offset: usize = 0;
                switch (repeating_group.repeat_mode) {
                    GRegexRepeatMode.zeroOrMore, GRegexRepeatMode.oneOrMore => {
                        var is_matching: bool = true;
                        var backstop_match_size: usize = 0;
                        var backstop: ?*const GRegexObject = null;
                        if (next_objects.len > 1) {
                            for (next_objects[1..]) |*potential_backstop| {
                                if (potential_backstop.is_backstop(self)) {
                                    backstop = potential_backstop;
                                    switch (potential_backstop.inner) {
                                        .matchGroup => |*match_group| {
                                            if (match_group.items.len > 0) {
                                                backstop = &match_group.items[0];
                                            }
                                        },
                                        else => {},
                                    }
                                    // std.debug.print("Using backstop:\n", .{});
                                    // if (backstop) |b| b.pretty_print(0, std.debug.print);
                                    break;
                                }
                                backstop_offset += 1;
                            }
                        }

                        if (backstop_offset > 0) backstop_offset = 0;

                        if (GRegexRepeatMode.oneOrMore == repeating_group.repeat_mode) {
                            var inner_match = try repeating_group.group.items[0].match(src[0..], next_objects[1..]);
                            if (!inner_match.is_match) {
                                return no_match;
                            }
                        }

                        while (is_matching and pos < src.len) {
                            for (repeating_group.group.items) |regex_obj, i| {
                                match_obj = try regex_obj.match(src[pos..], next_objects[1..]);
                                if (match_obj.is_match) {
                                    pos += match_obj.data.len;
                                } else {
                                    is_matching = false;
                                    pos += 1;
                                }

                                // check if it's the backstop
                                if (backstop) |b| {
                                    var backstop_match = no_match;
                                    backstop_match = try b.match(src[pos..], next_objects[1..]);
                                    if (backstop_match.is_match) {
                                        is_matching = false;
                                        backstop_match_size = backstop_match.data.len;
                                        break;
                                    }
                                }
                            }
                        }
                        if (backstop) |_| {
                            match_obj.backstop_offset = 0;
                        } else {
                            if (pos < src.len) {
                                pos -= 1;
                            }
                        }
                        match_obj.is_match = true;
                        match_obj.data = src[0..pos];
                    },
                    GRegexRepeatMode.zeroOrOne => {
                        for (repeating_group.group.items) |regex_obj, i| {
                            match_obj = try regex_obj.match(src[pos..], next_objects[1..]);
                            if (match_obj.is_match) {
                                pos += match_obj.data.len;
                            } else {
                                pos += 1;
                                break;
                            }
                        }
                        if (match_obj.is_match) {
                            match_obj.data = src[0..pos];
                        } else {
                            match_obj.data = "";
                        }
                        match_obj.is_match = true;
                    },
                    GRegexRepeatMode.nTimes => {},
                }
                return match_obj;
            },
        }
        return no_match;
    }

    pub fn pretty_print(self: *const GRegexObject, indent_level: u8, print: anytype) void {
        {
            var i: u8 = indent_level;
            while (i > 0) : (i -= 1) {
                print("  ", .{});
            }
            if (indent_level > 0) {
                print("| ", .{});
            }
        }

        var invert_char: []const u8 = "";
        if (self.invert) {
            invert_char = "!";
        }

        switch (self.*.inner) {
            .single => |inner| {
                if (inner[0] == '\t') {
                    print("{s}\\t\n", .{invert_char});
                } else if (inner[0] == '\n') {
                    print("{s}\\n\n", .{invert_char});
                } else if (inner[0] == '\r') {
                    print("{s}\\r\n", .{invert_char});
                } else if (inner[0] == ' ') {
                    print("{s}<space>\n", .{invert_char});
                } else {
                    print("{s}{s}\n", .{ invert_char, inner });
                }
            },
            .matchGroup => |inner| {
                print("{s}MatchGroup:\n", .{invert_char});
                const indent = indent_level + 1;
                for (inner.items) |regex_obj| {
                    regex_obj.pretty_print(indent, print);
                }
            },
            .repeatingGroup => |inner| {
                print("{s}RepeatGroup mode={s}:\n", .{ invert_char, inner.repeat_mode });
                const indent = indent_level + 1;
                for (inner.group.items) |regex_obj| {
                    regex_obj.pretty_print(indent, print);
                }
            },
            .range => |inner| {
                print("{s}'{c}(0x{x})' -> '{c}(0x{x})'\n", .{ invert_char, inner.min, inner.min, inner.max, inner.max });
            },
            .orgroup => |inner| {
                print("{s}OrGroup:\n", .{invert_char});
                const indent = indent_level + 1;
                for (inner.items) |regex_obj| {
                    regex_obj.pretty_print(indent, print);
                }
            },
        }
    }
};

const ReCompileError = error{ UnexpectedToken, UnhandledError, NotImplementedError, UnclosedGroupRegex, NestedMatchGroup };

const ReCompileObjectError = ReCompileError || error{OutOfMemory};

const ReSearchError = error{NotFoundError} || error{NotImplementedError} || error{DebugError};

const ReMatchGroup = struct {
    text: []const u8,
    pos: usize,
};

const ReParser = struct {
    sequence_mem: []GRegexObject,
    len: usize = 0,
    spec: []const u8 = "",
    allocator: *std.mem.Allocator,

    pub fn deinit(self: *ReParser) void {
        for (self.sequence_mem) |*regex_obj| {
            regex_obj.deinit();
        }
        self.allocator.free(self.sequence_mem);
        self.len = 0;
    }

    pub fn handle_resize(self: *ReParser, new_size: usize) !void {
        if (new_size < self.sequence_mem.len) {
            return;
        }

        var new_capacity = self.sequence_mem.len;
        while (new_capacity < new_size) {
            new_capacity *= 2;
        }
        var new_mem: []GRegexObject = try self.allocator.alloc(GRegexObject, new_capacity);

        std.mem.copy(GRegexObject, self.sequence_mem, new_mem);
        self.allocator.free(self.sequence_mem);
        self.sequence_mem = new_mem;
    }

    pub fn push(self: *ReParser, object: GRegexObject) !void {
        var new_capacity: usize = self.len + 1;
        try self.handle_resize(new_capacity);
        self.sequence_mem[self.len] = object;
        self.len += 1;
    }

    pub fn back(self: *const ReParser, object: GRegexObject) *GRegexObject {
        return &sequence_mem[self.len];
    }

    const ReParserBuilderContext = struct {
        spec: []const u8,
        pos: usize,
    };

    fn make_regex_obj_from_ctx(self: *ReParser, ctx: *ReParserBuilderContext, active_group: ?*GRegexObject) ReCompileObjectError!GRegexObject {
        const print = std.debug.print;
        // print("making inner_context for {s}, full={s}\n", .{ ctx.spec[ctx.pos..], ctx.spec });
        switch (ctx.spec[ctx.pos]) {
            '.' => {
                var push_obj: GRegexObject = .{ .inner = .{ .range = .{ .min = 1, .max = 255 } } };
                return push_obj;
            },
            'a'...'z', 'A'...'Z', '0'...'9', ':', ' ', '\n', '\r', '\t' => {
                // grab the next 3 characters to see if this is a range object
                // there's likely a more elegant way to handle this kind of windowing
                const max = if (ctx.pos + 3 < ctx.spec.len) ctx.pos + 3 else ctx.spec.len;
                var slice = ctx.spec[ctx.pos..max];
                var push_obj: GRegexObject = .{ .inner = .{
                    .single = slice[0..1],
                } };

                if (slice.len > 1) {
                    if (slice[1] == '-') {
                        push_obj = .{ .inner = .{ .range = .{
                            .min = slice[0],
                            .max = slice[2],
                        } } };
                        ctx.pos += 2;
                    }
                }
                return push_obj;
            },
            '[' => { // ored group case..
                // walk forward until we hit the closing brace
                var starting_pos: usize = ctx.pos;
                var lbrack_positions = ArrayList(usize).init(self.allocator);
                var closing_pos: usize = starting_pos;
                defer lbrack_positions.deinit();

                var slice = ctx.spec[starting_pos..];

                for (slice) |c, i| {
                    if (c == '[') {
                        try lbrack_positions.append(ctx.pos + i);
                        if (i > 1) {
                            if (ctx.spec[ctx.pos + i - 1] == '\\') {
                                // this is an escaped lbrack, dont capture it.
                                _ = lbrack_positions.pop();
                            }
                        }
                    }
                    if (c == ']') {
                        starting_pos = lbrack_positions.pop();
                        closing_pos = i + ctx.pos;
                    }
                }

                if (lbrack_positions.items.len == 0) {
                    const subslice_start = starting_pos + 1;
                    const subslice_end = closing_pos;

                    var sub_context = ReParserBuilderContext{ .spec = ctx.spec[subslice_start..subslice_end], .pos = 0 };

                    var or_group_obj = GRegexObject.make_orgroup(self.allocator);

                    while (sub_context.pos < sub_context.spec.len) : (sub_context.pos += 1) {
                        var spec_obj = try self.make_regex_obj_from_ctx(&sub_context, null);

                        switch (spec_obj.inner) // !!todo; change this to a look ahead instead
                        {
                            .repeatingGroup => {
                                _ = or_group_obj.inner.orgroup.pop();
                            },
                            else => {},
                        }

                        try or_group_obj.inner.orgroup.append(spec_obj);
                    }

                    // walk the position pointer forward, consuming all characters in the subcontext
                    ctx.pos = closing_pos;
                    return or_group_obj;
                } else {
                    const unclosed_pos = lbrack_positions.pop();
                    print("Unclosed bracket at position {d}: {c}", .{ unclosed_pos, ctx.spec[unclosed_pos] });
                    print("   Slice: '{s}'", .{ctx.spec});
                    return ReCompileError.UnexpectedToken;
                }
            },
            '$' => {
                ctx.pos += 1;
                return try GRegexObject.make_line_end(self.allocator);
            },
            '\\' => {
                // this is an escape character, capture the next character and create a single match
                var subslice_end = ctx.pos + 1;
                if (subslice_end < ctx.spec.len) {
                    var slice = ctx.spec[ctx.pos + 1 .. subslice_end + 1];
                    var regex_obj: GRegexObject = .{ .inner = .{
                        .single = slice,
                    } };

                    switch (slice[0]) {
                        's' => { // whitespace groups
                            regex_obj = try GRegexObject.make_whitespace(self.allocator);
                        },
                        'S' => {
                            regex_obj = try GRegexObject.make_whitespace(self.allocator);
                            regex_obj.invert = true;
                        },
                        'w' => {
                            regex_obj = try GRegexObject.make_alphanumeric(self.allocator);
                        },
                        'W' => {
                            regex_obj = try GRegexObject.make_alphanumeric(self.allocator);
                            regex_obj.invert = true;
                        },
                        'd' => {
                            regex_obj = try GRegexObject.make_digits(self.allocator);
                        },
                        'D' => {
                            regex_obj = try GRegexObject.make_digits(self.allocator);
                            regex_obj.invert = true;
                        },
                        else => {
                            // Literal character
                        },
                    }

                    // check if it's an escape sequence that matches one of the special sequences
                    ctx.pos += 1;
                    return regex_obj;
                }
                print("bad token:{c} at pos {d}\n", .{ ctx.spec[ctx.pos], ctx.pos });
                print("    {s}\n", .{ctx.spec});
                print("____", .{});
                var i: u32 = 0;
                while (i < ctx.pos) : (i += 1) {
                    print("_", .{});
                }
                print("^", .{});

                return ReCompileError.UnexpectedToken;
            },
            '!' => {
                if (self.len < 1) return ReCompileError.UnexpectedToken;
                var last_group = self.sequence_mem[self.len - 1];
                last_group.invert = !last_group.invert;
                self.len -= 1;
                return last_group;
            },
            // a better way would be to do a look-ahead on each GRegexObject creation and check for
            // one of these
            '*', // zero or more
            '+', // one or more
            '?', // zero or one
            '{', // n_times
            => { // repeating case, zero or more
                var re_group = try GRegexObject.make_repeating_group(ctx.spec[ctx.pos..], self.allocator);
                var last_group = self.sequence_mem[self.len - 1];
                if (active_group) |group| {
                    last_group = group.inner.matchGroup.pop();
                }

                // pop last object, and add it to re_group
                // std.debug.print("\n>>> patching_inner: \n", .{});
                // last_group.pretty_print(0, std.debug.print);
                // std.debug.print(">>> /patching \n\n", .{});

                try re_group.inner.repeatingGroup.group.append(last_group);
                return re_group; // return the repeating group
            },
            '(' => { // match group, create a new context from the inner
                if (active_group != null) {
                    return ReCompileError.NestedMatchGroup;
                }

                var rv = try GRegexObject.make_match_group(self.allocator);
                var end_pos = ctx.pos;

                var open_count: u32 = 1;
                var found: bool = false;
                for (ctx.spec[ctx.pos + 1 ..]) |character, index| {
                    if (character == '(') {
                        open_count += 1;
                    }
                    if (character == ')') {
                        end_pos = ctx.pos + index + 1;
                        open_count -= 1;
                        if (open_count == 0) {
                            found = true;
                            break;
                        }
                    }
                }
                if (found != true) {
                    std.debug.print("\nctx.spec = {s}\n", .{ctx.spec});
                    return ReCompileError.UnclosedGroupRegex;
                }
                var inner_ctx = ReParserBuilderContext{
                    .spec = ctx.spec[ctx.pos + 1 .. end_pos],
                    .pos = 0,
                };

                // std.debug.print("\ninner_ctx.spec = {s}\n", .{inner_ctx.spec});
                while (inner_ctx.pos < inner_ctx.spec.len) : (inner_ctx.pos += 1) {
                    var spec_obj = try self.make_regex_obj_from_ctx(&inner_ctx, &rv);
                    try rv.inner.matchGroup.append(spec_obj);
                }

                ctx.pos = end_pos;

                return rv;
            },
            ']' => {
                print("bad token:{c} at pos {d}\n", .{ ctx.spec[ctx.pos], ctx.pos });
                return ReCompileError.UnexpectedToken;
            },
            else => {
                print("bad token:{c} at pos {d}\n", .{ ctx.spec[ctx.pos], ctx.pos });
                print("    {s}\n", .{ctx.spec});
                print("____", .{});
                var i: u32 = 0;
                while (i < ctx.pos) : (i += 1) {
                    print("_", .{});
                }
                print("^", .{});

                return ReCompileError.UnexpectedToken;
            },
        }
        print("An unhandled error has occured remaining substr: {s}\n", .{ctx.spec[ctx.pos..]});
        return ReCompileError.UnhandledError;
    }

    pub fn parse_spec(self: *ReParser, spec: []const u8) !void {
        const print = std.debug.print;
        var pos: usize = 0;
        var ctx: ReParserBuilderContext = .{ .pos = 0, .spec = spec };
        while (ctx.pos < ctx.spec.len) : (ctx.pos += 1) {
            var spec_obj = try self.make_regex_obj_from_ctx(&ctx, null);
            switch (spec_obj.inner) // !!todo; change this to a look ahead instead
            {
                .repeatingGroup => {
                    self.len -= 1;
                },
                else => {},
            }
            try self.push(spec_obj);
        }
    }

    pub fn compile(spec: []const u8, allocator: *std.mem.Allocator) !ReParser {
        var alloc_ptr: []GRegexObject = try allocator.alloc(GRegexObject, 32);
        var rv = ReParser{ .sequence_mem = alloc_ptr, .allocator = allocator, .spec = spec };
        try rv.parse_spec(spec);
        return rv;
    }

    pub fn pretty_print(self: *const ReParser, printer: anytype) !void {
        var i: usize = 0;
        printer("{s}:\n", .{self.spec});
        while (i < self.len) : (i += 1) {
            self.sequence_mem[i].pretty_print(0, printer);
        }
    }

    const ParserContext = struct {
        src: []const u8,
        pos: usize,
        match_size: usize,
        pub fn make(src: []const u8) ParserContext {
            return ParserContext{ .src = src, .pos = 0, .match_size = 0 };
        }
        pub fn slice(self: *const ParserContext) []const u8 {
            return self.src[self.pos..];
        }
    };

    pub fn findstr_once(self: *const ReParser, src: []const u8) ![]const u8 {
        comptime const _debug: bool = false;
        var pos: usize = 0;
        while (pos < src.len) : (pos += 1) {
            var slice = src[pos..];
            var does_match = true;
            var parse_context = ParserContext.make(slice);

            var seq_id: usize = 0;
            while (seq_id < self.len) : (seq_id += 1) {
                const regex_obj = self.sequence_mem[seq_id];
                if (_debug) std.debug.print("trying match for '{s}'", .{parse_context.slice()});
                var match = try regex_obj.match(parse_context.slice(), self.sequence_mem[seq_id..self.len]);
                if (_debug) {
                    regex_obj.pretty_print(1);
                    std.debug.print("huh\n", .{});
                }

                if (!match.is_match) {
                    does_match = false;
                    if (_debug) {
                        std.debug.print("nomatch! {s} broken_match = \n", .{slice});
                        regex_obj.pretty_print(0, std.debug.print);
                    }
                    break;
                }

                // returns a count of the number of characters this matches
                if (match.is_match) {
                    // seq_id += match.backstop_offset;
                    parse_context.pos += match.data.len;
                    if (_debug) std.debug.print("len +{d} = {d} @off {}\n", .{
                        match.data.len,
                        parse_context.pos,
                        match.backstop_offset,
                    });
                    parse_context.match_size += match.data.len;
                }
            }

            if (does_match == true) {
                return slice[0..parse_context.match_size];
            } else {
                if (_debug) std.debug.print("nomatch2! {s} broken_match = \n", .{slice});
            }
        }
        return ""[0..0];
    }

    // finds first instance of a match in the target string and places matches into a groups
    // note this does not support nested groups
    //
    // this means you can't do .groups[0][0] in something like (lm(ao))
    pub fn find_once(self: ReParser, src: []const u8, allocator: *std.mem.Allocator) !ReMatch {
        var rv: ReMatch = try ReMatch.init(allocator);
        comptime const _debug: bool = false;

        var pos: usize = 0;

        while (pos < src.len) : (pos += 1) {
            var slice = src[pos..];
            var does_match = true;
            var parse_context = ParserContext.make(slice);

            var seq_id: usize = 0;

            while (seq_id < self.len) : (seq_id += 1) {
                const regex_obj = self.sequence_mem[seq_id];
                if (_debug) std.debug.print("trying match for '{s}'\n", .{parse_context.slice()});
                var match = try regex_obj.match(parse_context.slice(), self.sequence_mem[seq_id..self.len]);

                if (_debug) {
                    regex_obj.pretty_print(0, std.debug.print);
                    std.debug.print("matched! '{s}'\n", .{match.data});
                    std.debug.print("---\n", .{});
                }

                if (!match.is_match) {
                    does_match = false;
                    if (_debug) {
                        std.debug.print("nomatch! {s} broken_match = \n", .{slice});
                        regex_obj.pretty_print(0, std.debug.print);
                    }
                    break;
                }

                if (match.is_match) {
                    parse_context.pos += match.data.len;
                    parse_context.match_size += match.data.len;
                    switch (regex_obj.inner) {
                        .matchGroup => |match_group| {
                            var group_info: ReMatchGroup = .{ .pos = pos, .text = match.data };
                            if (_debug) std.debug.print("adding group: {s}\n", .{match.data});
                            try rv.push_group(group_info);
                        },
                        else => {},
                    }
                }
            }

            if (does_match == true) {
                rv.text = slice[0..parse_context.match_size];
                if (_debug) std.debug.print("Found results! {s}\n", .{rv.text});
                return rv;
            }
        }

        if (_debug) std.debug.print("Results not found! {s}\n", .{rv.text});
        rv.text = "";
        rv.is_match = false;
        return rv;
    }
};

// Testing suite ------------------------------------

fn test_noprint(comptime fmt: []const u8, args: anytype) void {}

fn leak_detection(allocator: *std.mem.Allocator) !void {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;

    var test_restr = "date: *([\\d\\-]*) name: *(.*)\\((.*)\\)$";
    var compiled = try ReParser.compile(test_restr, allocator);
    defer compiled.deinit();
    if (should_print) try compiled.pretty_print(print);

    var find = try re_find_once(test_restr, "date: 2077-06-24 name: adam jensen(occupation: killa)\n", allocator);
    defer find.deinit(); // find has an arraylist of regex objects, this should be de-initialized when out of scope.

    std.debug.assert(find.is_match);
    try expect(find.groups.items[1].text.len == "adam jensen".len);
    std.debug.assert(std.mem.eql(u8, "adam jensen", find.groups.items[1].text));

    try expect(find.groups.items[0].text.len == "2077-06-24".len);
    std.debug.assert(std.mem.eql(u8, "2077-06-24", find.groups.items[0].text));
}

test "gpa leak detection" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};

    defer {
        const leaked = gpa.deinit();
        if (leaked) expect(false) catch @panic("TEST FAIL");
    }

    try leak_detection(std.testing.allocator);
}

fn test_compile_inner(src: []const u8, allocator: *std.mem.Allocator, comptime should_print: bool) !void {
    var compiled = try ReParser.compile(src, allocator);
    defer compiled.deinit();
    try compiled.pretty_print(if (should_print) std.debug.print else test_noprint);
}

pub fn test_nomatch(re_str: []const u8, test_str: []const u8, allocator: *std.mem.Allocator) !void {
    var compiled = try ReParser.compile(re_str, allocator);
    defer compiled.deinit();
    var match = try compiled.findstr_once(test_str);
    if (match.len > 0) {
        std.debug.print("Assert Failed, it actually matched, {s} => {s}", .{ re_str, test_str });
    }
    try expect(match.len == 0);
}

pub fn test_groups(
    re_str: []const u8,
    test_str: []const u8,
    group0_str: []const u8,
    group_count: usize,
    alloc: *std.mem.Allocator,
) !void {
    var compiled = try ReParser.compile(re_str, alloc);
    defer compiled.deinit();

    var findstr = try compiled.findstr_once(test_str);
    try expect(findstr.len > 0);
    var rematch = try compiled.find_once(test_str, alloc);
    defer rematch.deinit();

    expect(std.mem.eql(u8, rematch.groups.items[0].text, group0_str)) catch {
        std.debug.print("'{s}'\n!=\n'{s}'", .{ rematch.groups.items[0].text, group0_str });
        @panic("Test Failed");
    };
    try expect(rematch.groups.items.len == group_count);
}

pub fn test_match(re_str: []const u8, test_str: []const u8, alloc: *std.mem.Allocator, assert_len: usize) !void {
    var compiled = try ReParser.compile(re_str, alloc);
    defer compiled.deinit();
    var match = try compiled.findstr_once(test_str);
    if (match.len != assert_len) {
        std.debug.print("Assert Failed, matched length {d}, expected {d} string='{s}' \n", .{ match.len, assert_len, match });
    }
    try expect(match.len == assert_len);
}

test "ipc_testing_match_groups" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;
    defer print("/end \n", .{});
    print("\n", .{});
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const alloc = &arena.allocator;

    try test_groups("lm(ao)", "one two three lmao four", "ao", 1, alloc);
    try test_groups("l(ma)o", "one two three lmao four", "ma", 1, alloc);
}

test "ipc_repeating_groups" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;
    print("\n", .{});
    defer print("/end \n", .{});
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = &arena.allocator;

    {
        var compiled = try ReParser.compile("lmao:.*", alloc);
        defer compiled.deinit();
        try compiled.pretty_print(print);
        var match = try re_findstr_once("lmao:.*c", "lmao: wutangclan", alloc);
        var match2 = try re_findstr_once("lmao:.*x", "lmao:tx", alloc);
        var match3 = try re_findstr_once("lmao:.*x?y", "random lmao:ty text", alloc);
        try expect(match.len == 13);
        try expect(match2.len == 7);
        try expect(match3.len == match2.len);
    }

    try test_match("lmao:x?", "hfjdkahfls lmao:x text", alloc, 6);
    try test_match("lmao:x*", "hfjdkahfls lmao:xxt text", alloc, 7);
    try test_match("lmao:x+", "hfjdkahfls lmao:xxt text", alloc, 7);
    try test_match("lmao:x+", "hfjdkahfls lmao:xxxxxt text", alloc, 10);
    try test_match("lmao:.*", "hfjdkahfls\n lmao:xxt text", alloc, 13);
    try test_match("lmao:x?", "fhjdaklfhsdjkal lmao: text", alloc, 5);
    try test_match("(lm)ao", "fhjdaklfhsdjkal lmao: text", alloc, 4);
    try test_nomatch("lmao:x+", " dfjsaf lmao:yx c", alloc);
}

test "epc_orgroup_matching" {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = &arena.allocator;

    try expect((try re_findstr_once("p.ter", "peter", alloc)).len == 5);
    try expect((try re_findstr_once("p.ter", "pater", alloc)).len == 5);
    try expect((try re_findstr_once("p.ter", "p0ter", alloc)).len == 5);
    try expect((try re_findstr_once("pa!ter", "p0ter", alloc)).len == 5);
    try expect((try re_findstr_once("p[xyt]ter", "pyter", alloc)).len == 5);
}

test "ipc_parse_strings" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const alloc = &arena.allocator;
    defer arena.deinit();

    var compiled = try ReParser.compile("p.ter", alloc);
    defer compiled.deinit();
    {
        var test_str = "this guy is named peter!!"; // contains sequence h e l l o
        var slice = compiled.findstr_once(test_str);
    }
    {
        var test_str = "this guy is named pater!!"; // contains sequence h e l l o
        var slice = compiled.findstr_once(test_str);
    }
}

test "ipc_compile_regex" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const alloc = &arena.allocator;

    {
        var test_str = ".helloa-zA-Z"; // contains sequence h e l l o
        var compiled = try ReParser.compile(test_str, alloc);
        defer compiled.deinit();
        var i: usize = 0;
        if (should_print) try compiled.pretty_print();
    }

    {
        var test_str = "0x[\\[abcdef]223";
        var compiled = try ReParser.compile(test_str, alloc);
        defer compiled.deinit();
        var i: usize = 0;
        if (should_print) try compiled.pretty_print();
    }

    {
        var test_str = "0x[\\[abcdef]2+23";
        var compiled = try ReParser.compile(test_str, alloc);
        defer compiled.deinit();
        var i: usize = 0;
        if (should_print) try compiled.pretty_print();
    }

    {
        var test_str = "[0[a-z]]"; // contains sequence nested orGroup sequences
        var compiled = try ReParser.compile(test_str, alloc);
        defer compiled.deinit();
        var i: usize = 0;
        if (should_print) try compiled.pretty_print();
    }

    {
        var test_str = "\\s\\S\\w\\W\\d\\D"; // contains sequence nested orGroup sequences
        var compiled = try ReParser.compile(test_str, alloc);
        defer compiled.deinit();
        var i: usize = 0;
        if (should_print) try compiled.pretty_print();
    }

    {
        var test_str = "\\s\\S\\w\\W\\d\\D"; // contains sequence nested orGroup sequences
        print("testing string: {s}\n", .{test_str});
    }
}

test "ipc_compile_regex_with_groups" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;
    var alloc = std.testing.allocator;

    try test_compile_inner("(wu)tang", alloc, should_print);
    try test_compile_inner("(wu)tang (2mercy)", alloc, should_print);
}

test "ipc_compile_and_use_group_regex" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    var alloc = &arena.allocator;

    defer arena.deinit();
    {
        var compiled = try ReParser.compile("l(ma)(o)", alloc);
        try compiled.pretty_print(print);
        defer compiled.deinit();
    }
}

test "epc_groups_and_conditionals" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;
    var alloc = std.testing.allocator;

    var test_restr = "date: *([\\d\\-]*) name: *(.*)\\((.*)\\)$";
    var compiled = try ReParser.compile(test_restr, alloc);
    defer compiled.deinit();
    if (should_print) try compiled.pretty_print(print);

    var find = try re_find_once(test_restr, "date: 2077-06-24 name: adam jensen(occupation: killa)\n", alloc);
    defer find.deinit(); // find has an arraylist of regex objects, this should be de-initialized when out of scope.

    std.debug.assert(find.is_match);

    try expect(find.groups.items[1].text.len == "adam jensen".len);
    std.debug.assert(std.mem.eql(u8, "adam jensen", find.groups.items[1].text));

    try expect(find.groups.items[0].text.len == "2077-06-24".len);
    std.debug.assert(std.mem.eql(u8, "2077-06-24", find.groups.items[0].text));
}

test "epc_random_sequences" {
    const should_print: bool = false;
    const print = if (should_print) std.debug.print else test_noprint;
    var alloc = std.testing.allocator;
}
