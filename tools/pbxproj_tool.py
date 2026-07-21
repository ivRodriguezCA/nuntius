#!/usr/bin/env python3
"""
Idempotent, manifest-driven registration of source files in nuntius.xcodeproj/project.pbxproj.

A missing PBXSourcesBuildPhase entry is a SILENT NO-OP, not an error: the file simply never
compiles and the failure surfaces at link time pointing at the caller. Hand-editing four sections
per file across dozens of files is not viable, so this tool owns all four:

  1. PBXFileReference   (always)
  2. PBXBuildFile       (.m always; .h only when Public)
  3. PBXGroup child     (always)
  4. PBXSourcesBuildPhase (.m) or PBXHeadersBuildPhase (.h, Public only)

Project-visibility headers get a file reference and a group entry but NO PBXBuildFile and NO
Headers-phase entry. They remain importable from the test target through Xcode's generated
project header map, so no HEADER_SEARCH_PATHS work is needed.

Every mutation is scoped to a single object's body, located by extracting the span between an
object's `\\n\\t\\t<ID> ... = {` opening and its matching `\\n\\t\\t};`. Matching an id with a
`.*?` that can cross an object boundary silently appends to the WRONG object, which lints clean and
puts files in a group nobody asked for.

Re-running with the same manifest is a no-op. Always follow a mutation with:

    plutil -lint nuntius.xcodeproj/project.pbxproj

Usage:
    pbxproj_tool.py add --project PATH --group NAME --target NAME \\
        --source FILE.m [--source ...] \\
        --public-header FILE.h [--public-header ...] \\
        --project-header FILE.h [--project-header ...]

    pbxproj_tool.py remove --project PATH --file FILE [--file ...]

    pbxproj_tool.py remove-group --project PATH --name NAME [--name ...]

    pbxproj_tool.py verify --project PATH --file FILE [--file ...]
"""

import argparse
import hashlib
import re
import sys

FILE_TYPES = {
    '.h': 'sourcecode.c.h',
    '.m': 'sourcecode.c.objc',
    '.c': 'sourcecode.c.c',
}

OBJECT_ID = r'[0-9A-F]{24}'

# The OpenStep plist grammar pbxproj uses accepts an unquoted string only when every character is
# in this set. A filename containing anything else -- '+' is the one that actually bites, as in
# `IREnvironment+Testing.h` -- MUST be quoted, or the whole file stops parsing and `plutil -lint`
# reports a useless "Unexpected character / at line 1" from the leading `// !$*UTF8*$!` comment.
UNQUOTED_SAFE = re.compile(r'^[A-Za-z0-9_$./-]+$')


def plist_string(value):
    """Quote a value for the OpenStep plist grammar if it is not bare-safe."""
    if UNQUOTED_SAFE.match(value):
        return value
    return '"%s"' % value.replace('\\', '\\\\').replace('"', '\\"')


class Pbxproj(object):

    def __init__(self, path):
        self.path = path
        with open(path, 'r', encoding='utf-8') as handle:
            self.text = handle.read()
        self.existing_ids = set(re.findall(r'\b(' + OBJECT_ID + r')\b', self.text))

    # ---------------------------------------------------------------- ids

    def make_id(self, seed):
        """Deterministic 24-hex id, so re-running produces stable output."""
        counter = 0
        while True:
            digest = hashlib.sha256(
                ('nuntius-v4:' + seed + ':' + str(counter)).encode('utf-8')
            ).hexdigest().upper()
            candidate = digest[:24]
            if candidate not in self.existing_ids:
                self.existing_ids.add(candidate)
                return candidate
            counter += 1

    # ------------------------------------------------------- object spans

    def object_body_span(self, object_id):
        """(start, end) of the body of the top-level object `object_id`.

        Anchored on a line start with exactly two tabs, with any comment confined to that same
        line, so the match cannot begin inside another object's children list.
        """
        opening = re.search(
            r'\n\t\t' + object_id + r'(?: /\*[^\n]*\*/)? = \{\n', self.text)
        if not opening:
            raise SystemExit('object not found: ' + object_id)

        start = opening.end()
        closing = re.compile(r'\n\t\t\};').search(self.text, start)
        if not closing:
            raise SystemExit('unterminated object: ' + object_id)

        return start, closing.start()

    def object_isa(self, object_id):
        start, end = self.object_body_span(object_id)
        match = re.search(r'isa = (\w+);', self.text[start:end])
        return match.group(1) if match else None

    # ------------------------------------------------------------ lookups

    def file_ref_id(self, filename):
        match = re.search(
            r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(filename) +
            r' \*/ = \{isa = PBXFileReference;', self.text)
        return match.group(1) if match else None

    def group_id(self, name):
        match = re.search(
            r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(name) +
            r' \*/ = \{\n\t\t\tisa = PBXGroup;', self.text)
        return match.group(1) if match else None

    def target_phase_id(self, target_name, phase_isa):
        """The build-phase object id belonging to a named PBXNativeTarget."""
        target_match = re.search(
            r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(target_name) +
            r' \*/ = \{\n\t\t\tisa = PBXNativeTarget;', self.text)
        if not target_match:
            raise SystemExit('target not found: ' + target_name)

        start, end = self.object_body_span(target_match.group(1))
        phases = re.search(r'buildPhases = \(\n(.*?)\n\t\t\t\);', self.text[start:end], re.S)
        if not phases:
            raise SystemExit('no buildPhases for target: ' + target_name)

        for phase_id in re.findall(r'\b(' + OBJECT_ID + r')\b', phases.group(1)):
            if self.object_isa(phase_id) == phase_isa:
                return phase_id

        raise SystemExit('no %s in target %s' % (phase_isa, target_name))

    # ----------------------------------------------------------- mutation

    def insert_before(self, marker, line):
        index = self.text.index(marker)
        self.text = self.text[:index] + line + self.text[index:]

    def add_file_reference(self, filename):
        existing = self.file_ref_id(filename)
        if existing:
            return existing, False

        extension = filename[filename.rindex('.'):]
        file_type = FILE_TYPES.get(extension)
        if not file_type:
            raise SystemExit('unhandled file extension: ' + filename)

        ref_id = self.make_id('fileref:' + filename)
        entry = ('\t\t%s /* %s */ = {isa = PBXFileReference; fileEncoding = 4; '
                 'lastKnownFileType = %s; path = %s; sourceTree = "<group>"; };\n'
                 % (ref_id, filename, file_type, plist_string(filename)))
        self.insert_before('/* End PBXFileReference section */', entry)
        return ref_id, True

    def add_build_file(self, filename, ref_id, phase_label, public, compiler_flags=None):
        """Register a PBXBuildFile.

        `compiler_flags` becomes a per-file COMPILER_FLAGS setting. SPEC §13.2 wants
        -Wunused-result promoted to an error across the crypto layer; scoping it per file rather
        than per target is what keeps it off the vendored libsodium headers, which do not compile
        clean under it.

        NOTE: an existing entry is returned untouched, so changing the flags for a file already
        registered requires removing its PBXBuildFile line first. Idempotency is the priority —
        silently rewriting build settings on every run is worse than requiring one manual step.
        """
        match = re.search(
            r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(filename) + r' in ' +
            re.escape(phase_label) + r' \*/ = \{isa = PBXBuildFile;', self.text)
        if match:
            return match.group(1), False

        build_id = self.make_id('buildfile:' + phase_label + ':' + filename)

        attributes = []
        if public:
            attributes.append('ATTRIBUTES = (Public, ); ')
        if compiler_flags:
            attributes.append('COMPILER_FLAGS = "%s"; ' % compiler_flags)

        settings = ' settings = {%s};' % ''.join(attributes) if attributes else ''
        entry = ('\t\t%s /* %s in %s */ = {isa = PBXBuildFile; fileRef = %s /* %s */;%s };\n'
                 % (build_id, filename, phase_label, ref_id, filename, settings))
        self.insert_before('/* End PBXBuildFile section */', entry)
        return build_id, True

    def ensure_group(self, group_name, parent_group_id):
        existing = self.group_id(group_name)
        if existing:
            return existing

        new_id = self.make_id('group:' + group_name)
        block = ('\t\t%s /* %s */ = {\n'
                 '\t\t\tisa = PBXGroup;\n'
                 '\t\t\tchildren = (\n'
                 '\t\t\t);\n'
                 '\t\t\tname = %s;\n'
                 '\t\t\tsourceTree = "<group>";\n'
                 '\t\t};\n' % (new_id, group_name, plist_string(group_name)))
        self.insert_before('/* End PBXGroup section */', block)

        self.append_to_list(parent_group_id, 'children', new_id, group_name)
        return new_id

    def append_to_list(self, container_id, list_name, child_id, comment):
        """Append `child_id` to the `children` or `files` list of object `container_id`."""
        start, end = self.object_body_span(container_id)
        body = self.text[start:end]

        opening = re.search(r'\n?\t\t\t' + list_name + r' = \(\n', body)
        if not opening:
            raise SystemExit('no %s list in %s' % (list_name, container_id))

        closing = re.compile(r'\t\t\t\);').search(body, opening.end())
        if not closing:
            raise SystemExit('unterminated %s list in %s' % (list_name, container_id))

        if re.search(r'\b' + child_id + r'\b', body[opening.end():closing.start()]):
            return False

        entry = '\t\t\t\t%s /* %s */,\n' % (child_id, comment)
        insertion = start + closing.start()
        self.text = self.text[:insertion] + entry + self.text[insertion:]
        return True

    def remove_file(self, filename):
        """Unregister `filename` from all four sections.

        Removal is by OBJECT ID, never by filename: a `children`/`files` list entry carries the
        filename only inside a `/* ... */` comment, and Xcode is free to rewrite or drop those
        comments. Deleting a line because its comment matched would leave the real reference behind
        under a stale comment, and the build would then fail on a file the tool just reported as
        removed. The reverse of `add`: build-phase entry, group child, PBXBuildFile, PBXFileReference.
        """
        ref_id = self.file_ref_id(filename)
        if not ref_id:
            return False

        for build_id in re.findall(
                r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(filename) +
                r' in \w+ \*/ = \{isa = PBXBuildFile;', self.text):
            # The phase `files` entry and the PBXBuildFile object itself.
            self.text = re.sub(r'\n\t\t\t\t' + build_id + r' /\*[^\n]*\*/,', '', self.text)
            self.text = re.sub(r'\n\t\t' + build_id + r' /\*[^\n]*\*/ = \{isa = PBXBuildFile;[^\n]*\n',
                               '\n', self.text)

        # The group `children` entry, then the file reference.
        self.text = re.sub(r'\n\t\t\t\t' + ref_id + r' /\*[^\n]*\*/,', '', self.text)
        self.text = re.sub(r'\n\t\t' + ref_id + r' /\*[^\n]*\*/ = \{isa = PBXFileReference;[^\n]*\n',
                           '\n', self.text)

        if re.search(r'\b' + ref_id + r'\b', self.text):
            raise SystemExit('dangling reference to %s after removing %s' % (ref_id, filename))

        return True

    def remove_empty_groups(self, name):
        """Drop every PBXGroup called `name` whose `children` list is empty.

        Removing the last file from a group leaves the group behind, and an empty group in the
        navigator reads as "the files are somewhere else" rather than "the files are gone". Refuses
        to touch a non-empty group: a group that still has children is a group whose files were not
        all removed, and silently deleting it would orphan them.

        Names are NOT unique in a pbxproj -- this project has two groups called `Services`, one per
        target -- so every match is considered, not just the first.
        """
        removed = 0

        while True:
            match = re.search(
                r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(name) +
                r' \*/ = \{\n\t\t\tisa = PBXGroup;\n\t\t\tchildren = \(\n\t\t\t\);\n'
                r'(?:\t\t\t[^\n]*\n)*?\t\t\};\n', self.text)
            if not match:
                break

            group_id = match.group(1)
            self.text = self.text[:match.start() + 1] + self.text[match.end():]
            # The parent group's `children` entry pointing at it.
            self.text = re.sub(r'\n\t\t\t\t' + group_id + r' /\*[^\n]*\*/,', '', self.text)

            if re.search(r'\b' + group_id + r'\b', self.text):
                raise SystemExit('dangling reference to group %s (%s)' % (name, group_id))

            removed += 1

        if re.search(r'\n\t\t' + OBJECT_ID + r' /\* ' + re.escape(name) +
                     r' \*/ = \{\n\t\t\tisa = PBXGroup;', self.text):
            raise SystemExit('group is not empty, refusing to remove: ' + name)

        return removed

    def ensure_script_phase(self, target_name, phase_name, script, first=True):
        """Add a PBXShellScriptBuildPhase to a target, idempotently, keyed on its name.

        `first` places it ahead of Sources, which is what a lint wants: a banned-API violation
        should stop the build before the file that contains it is compiled, not after.
        """
        target_match = re.search(
            r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(target_name) +
            r' \*/ = \{\n\t\t\tisa = PBXNativeTarget;', self.text)
        if not target_match:
            raise SystemExit('target not found: ' + target_name)

        target_id = target_match.group(1)

        existing = re.search(
            r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(phase_name) +
            r' \*/ = \{\n\t\t\tisa = PBXShellScriptBuildPhase;', self.text)
        if existing:
            return existing.group(1), False

        phase_id = self.make_id('scriptphase:' + target_name + ':' + phase_name)

        # `alwaysOutOfDate = 1` because the phase has no declared outputs: without it Xcode skips
        # the phase on an incremental build, which is how a lint quietly stops running.
        block = ('\t\t%s /* %s */ = {\n'
                 '\t\t\tisa = PBXShellScriptBuildPhase;\n'
                 '\t\t\talwaysOutOfDate = 1;\n'
                 '\t\t\tbuildActionMask = 2147483647;\n'
                 '\t\t\tfiles = (\n'
                 '\t\t\t);\n'
                 '\t\t\tinputFileListPaths = (\n'
                 '\t\t\t);\n'
                 '\t\t\tinputPaths = (\n'
                 '\t\t\t);\n'
                 '\t\t\tname = %s;\n'
                 '\t\t\toutputFileListPaths = (\n'
                 '\t\t\t);\n'
                 '\t\t\toutputPaths = (\n'
                 '\t\t\t);\n'
                 '\t\t\trunOnlyForDeploymentPostprocessing = 0;\n'
                 '\t\t\tshellPath = /bin/sh;\n'
                 '\t\t\tshellScript = %s;\n'
                 '\t\t};\n'
                 % (phase_id, phase_name, plist_string(phase_name), plist_string(script)))

        if '/* Begin PBXShellScriptBuildPhase section */' in self.text:
            self.insert_before('/* End PBXShellScriptBuildPhase section */', block)
        else:
            self.insert_before(
                '/* Begin PBXSourcesBuildPhase section */',
                '/* Begin PBXShellScriptBuildPhase section */\n' + block +
                '/* End PBXShellScriptBuildPhase section */\n\n')

        start, end = self.object_body_span(target_id)
        body = self.text[start:end]
        opening = re.search(r'\n\t\t\tbuildPhases = \(\n', body)
        if not opening:
            raise SystemExit('no buildPhases list in target ' + target_name)

        if first:
            insertion = start + opening.end()
        else:
            closing = re.compile(r'\t\t\t\);').search(body, opening.end())
            insertion = start + closing.start()

        entry = '\t\t\t\t%s /* %s */,\n' % (phase_id, phase_name)
        self.text = self.text[:insertion] + entry + self.text[insertion:]

        return phase_id, True

    def write(self):
        with open(self.path, 'w', encoding='utf-8') as handle:
            handle.write(self.text)


def command_add(args):
    project = Pbxproj(args.project)

    parent_group = project.group_id(args.parent_group)
    if not parent_group:
        raise SystemExit('parent group not found: ' + args.parent_group)

    group_id = project.ensure_group(args.group, parent_group)
    sources_phase = project.target_phase_id(args.target, 'PBXSourcesBuildPhase')

    # Resolved lazily: a unit-test bundle has no PBXHeadersBuildPhase at all, and asking for one
    # it does not have must not stop source registration.
    headers_phase = None
    if args.public_header:
        headers_phase = project.target_phase_id(args.target, 'PBXHeadersBuildPhase')

    added = []

    for filename in args.project_header or []:
        ref_id, is_new = project.add_file_reference(filename)
        project.append_to_list(group_id, 'children', ref_id, filename)
        added.append((filename, 'project-header', ref_id, is_new))

    for filename in args.public_header or []:
        ref_id, is_new = project.add_file_reference(filename)
        project.append_to_list(group_id, 'children', ref_id, filename)
        build_id, _ = project.add_build_file(filename, ref_id, 'Headers', public=True)
        project.append_to_list(headers_phase, 'files', build_id, '%s in Headers' % filename)
        added.append((filename, 'public-header', ref_id, is_new))

    for filename in args.source or []:
        ref_id, is_new = project.add_file_reference(filename)
        project.append_to_list(group_id, 'children', ref_id, filename)
        build_id, _ = project.add_build_file(filename, ref_id, 'Sources', public=False,
                                             compiler_flags=args.compiler_flags)
        project.append_to_list(sources_phase, 'files', build_id, '%s in Sources' % filename)
        added.append((filename, 'source', ref_id, is_new))

    project.write()

    for filename, role, ref_id, is_new in added:
        print('%-28s %-15s %s %s' % (filename, role, ref_id, 'added' if is_new else 'existing'))


def command_remove(args):
    project = Pbxproj(args.project)
    results = [(filename, project.remove_file(filename)) for filename in args.file]
    project.write()

    for filename, removed in results:
        print('%-32s %s' % (filename, 'removed' if removed else 'not registered'))


def command_remove_group(args):
    project = Pbxproj(args.project)
    results = [(name, project.remove_empty_groups(name)) for name in args.name]
    project.write()

    for name, count in results:
        print('%-32s %s' % (name, ('removed x%d' % count) if count else 'not present'))


def command_add_script_phase(args):
    project = Pbxproj(args.project)
    phase_id, is_new = project.ensure_script_phase(args.target, args.name, args.script,
                                                   first=not args.last)
    project.write()

    print('%-32s %s %s' % (args.name, phase_id, 'added' if is_new else 'existing'))


def command_verify(args):
    """Confirm a file is registered where the build actually looks for it."""
    project = Pbxproj(args.project)
    failures = 0

    for filename in args.file:
        ref_id = project.file_ref_id(filename)
        if not ref_id:
            print('MISSING file reference: ' + filename)
            failures += 1
            continue

        if filename.endswith('.m'):
            sources = project.target_phase_id(args.target, 'PBXSourcesBuildPhase')
            start, end = project.object_body_span(sources)
            build = re.search(
                r'\n\t\t(' + OBJECT_ID + r') /\* ' + re.escape(filename) +
                r' in Sources \*/ = \{isa = PBXBuildFile;', project.text)
            if not build or not re.search(r'\b' + build.group(1) + r'\b',
                                          project.text[start:end]):
                print('MISSING Sources phase entry: ' + filename)
                failures += 1
                continue

        print('ok  ' + filename)

    return 1 if failures else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)

    add = sub.add_parser('add')
    add.add_argument('--project', required=True)
    add.add_argument('--group', required=True)
    add.add_argument('--target', required=True)
    add.add_argument('--parent-group', default='nuntius',
                     help='PBXGroup the new group is nested under (default: nuntius)')
    add.add_argument('--source', action='append')
    add.add_argument('--public-header', action='append')
    add.add_argument('--project-header', action='append')
    add.add_argument('--compiler-flags', default=None,
                     help='Per-file COMPILER_FLAGS applied to every --source in this invocation, '
                          'e.g. "-Werror=unused-result" for the SPEC 13.2 crypto layer')

    remove = sub.add_parser('remove')
    remove.add_argument('--project', required=True)
    remove.add_argument('--file', action='append', required=True)

    remove_group = sub.add_parser('remove-group')
    remove_group.add_argument('--project', required=True)
    remove_group.add_argument('--name', action='append', required=True)

    script_phase = sub.add_parser('add-script-phase')
    script_phase.add_argument('--project', required=True)
    script_phase.add_argument('--target', required=True)
    script_phase.add_argument('--name', required=True)
    script_phase.add_argument('--script', required=True)
    script_phase.add_argument('--last', action='store_true',
                              help='append after the existing phases instead of before Sources')

    verify = sub.add_parser('verify')
    verify.add_argument('--project', required=True)
    verify.add_argument('--file', action='append', required=True)
    verify.add_argument('--target', default='nuntius')

    args = parser.parse_args()

    if args.command == 'add':
        command_add(args)
        return 0

    if args.command == 'remove':
        command_remove(args)
        return 0

    if args.command == 'remove-group':
        command_remove_group(args)
        return 0

    if args.command == 'add-script-phase':
        command_add_script_phase(args)
        return 0

    return command_verify(args)


if __name__ == '__main__':
    sys.exit(main())
