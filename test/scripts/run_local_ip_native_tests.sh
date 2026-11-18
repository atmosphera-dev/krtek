#!/usr/bin/env bash
# Run only inside the assigned project builder, with disk-backed TMPDIR.
set -euo pipefail
root=$(cd "$(dirname "$0")/../.." && pwd)
native="$root/talpid-lan-forwarder/native"
out=${KRTEK_EVIDENCE_DIR:?set KRTEK_EVIDENCE_DIR to a disk-backed evidence directory}
mkdir -p "$out"
python3 - "$native" <<'PY'
import hashlib, json, pathlib, sys
n = pathlib.Path(sys.argv[1])
m = json.loads((n / 'lwip-source.json').read_text())
assert m['commit'] == '77dcd25a72509eb83f72b033d219b1d40cd8eb95'
files = {str(p.relative_to(n / 'vendor/lwip')): hashlib.sha256(p.read_bytes()).hexdigest()
         for p in (n / 'vendor/lwip').rglob('*') if p.is_file()}
assert files == m['sha256'], 'pristine vendor file inventory mismatch'
print(f'vendor: {len(files)} pristine files, {m["commit"]}')
PY
python3 "$native/tests/check_notices.py"
flags=(-std=c11 -O1 -g -Wall -Wextra -Werror -fno-omit-frame-pointer
    -fvisibility=hidden -I"$native" -I"$native/vendor/lwip/src/include")
android=0
ffi=0
for argument in "$@"; do
    case $argument in
        --sanitize) flags+=(-fsanitize=address,undefined) ;;
        --android) android=1 ;;
        --ffi) ffi=1 ;;
        *) echo "usage: $0 [--sanitize] [--android] [--ffi]" >&2; exit 2 ;;
    esac
done
sources=()
while IFS= read -r source; do
    [[ -z $source ]] || sources+=("$native/vendor/lwip/$source")
done < "$native/sources.txt"
# Stock ND has unused declarations with SLAAC/RS disabled; keep the port's own
# warnings strict, and suppress only those two classes in upstream translation units.
objects=()
for source in "${sources[@]}"; do
    object="$out/$(basename "${source%.c}").o"
    "${CC:-cc}" "${flags[@]}" -Wno-unused-parameter -Wno-unused-variable -c "$source" -o "$object"
    objects+=("$object")
done
"${CC:-cc}" "${flags[@]}" "$native/tests/bridge_test.c" "${objects[@]}" \
    -Wl,-Map,"$out/bridge.map" -o "$out/bridge_test"
"$out/bridge_test"
# Clock fixtures are separate processes, never clock manipulation in Rust tests.
"$out/bridge_test" expiry
"$out/bridge_test" pressure
"$out/bridge_test" clock
size "$out/bridge_test" | tee "$out/bridge.size"
nm -S --size-sort "$out/bridge_test" > "$out/bridge.symbols"
if ((ffi)); then
    mkdir -p "$out/ffi"
    objects=()
    for source in "$native/krtek_lwip.c" "${sources[@]}"; do
        object="$out/ffi/$(basename "${source%.c}").o"
        "${CC:-cc}" -std=c11 -O1 -g -fvisibility=hidden \
            -I"$native" -I"$native/vendor/lwip/src/include" -c "$source" -o "$object"
        objects+=("$object")
    done
    ar crs "$out/ffi/libkrtek_lwip.a" "${objects[@]}"
    rustc --edition 2024 -Dwarnings "$native/tests/ffi_test.rs" \
        -L "native=$out/ffi" -l static=krtek_lwip -o "$out/ffi/ffi_test"
    "$out/ffi/ffi_test"
fi
if ((android)); then
    toolchain=${NDK_TOOLCHAIN_DIR:?set the existing NDK toolchain directory}
    for target in armv7-linux-androideabi aarch64-linux-android i686-linux-android x86_64-linux-android; do
        compiler_var=CC_${target//-/_}
        compiler=${!compiler_var:?set the existing Cargo target-specific NDK compiler}
        abiout="$out/$target"
        mkdir -p "$abiout"
        abiflags=(-std=c11 -Os -g -Wall -Wextra -Werror -fPIC -fvisibility=hidden
            -ffunction-sections -fdata-sections -fstack-usage -MMD
            -I"$native" -I"$native/vendor/lwip/src/include")
        objects=()
        for source in "$native/krtek_lwip.c" "${sources[@]}"; do
            object="$abiout/$(basename "${source%.c}").o"
            extra=()
            if [[ $source == "$native/vendor/"* ]]; then
                extra=(-Wno-unused-parameter -Wno-unused-variable)
            fi
            "$compiler" "${abiflags[@]}" "${extra[@]}" -c "$source" -o "$object"
            objects+=("$object")
        done
        "$toolchain/llvm-ar" crs "$abiout/libkrtek_lwip.a" "${objects[@]}"
        "$compiler" -shared -Wl,--no-undefined -Wl,-z,max-page-size=16384 \
            -Wl,-Map,"$abiout/bridge.map" -Wl,--whole-archive "$abiout/libkrtek_lwip.a" \
            -Wl,--no-whole-archive -o "$abiout/libkrtek_lwip-proof.so"
        "$compiler" "${abiflags[@]}" -c "$native/tests/contract_test.c" -o "$abiout/contract.o"
        "$compiler" "${abiflags[@]}" -c "$native/tests/layout_test.c" -o "$abiout/layout.o"
        "$toolchain/llvm-readelf" -h -l -Ws "$abiout/libkrtek_lwip-proof.so" > "$abiout/elf.txt"
        "$toolchain/llvm-readelf" -h "$abiout/libkrtek_lwip.a" > "$abiout/archive.txt"
        "$toolchain/llvm-nm" -S --size-sort "$abiout/layout.o" > "$abiout/layout.txt"
        "$toolchain/llvm-nm" -S --size-sort "$abiout/libkrtek_lwip-proof.so" > "$abiout/symbols.txt"
        "$toolchain/llvm-nm" -D --defined-only "$abiout/libkrtek_lwip-proof.so" > "$abiout/exports.txt"
        "$toolchain/llvm-size" -A "$abiout/libkrtek_lwip-proof.so" > "$abiout/sections.txt"
        "$compiler" --version > "$abiout/compiler.txt"
        python3 - "$abiout" "$target" "$native" <<'PY'
import json, pathlib, re, shlex, struct, sys
p = pathlib.Path(sys.argv[1])
sections = {}
for line in (p/'sections.txt').read_text().splitlines():
    parts = line.split()
    if len(parts) == 3 and parts[0].startswith('.'):
        sections[parts[0]] = int(parts[1])
binary = (p/'libkrtek_lwip-proof.so').read_bytes()
assert binary[:4] == b'\x7fELF' and binary[5] == 1
if binary[4] == 2:
    shoff, phoff = struct.unpack_from('<Q',binary,40)[0], struct.unpack_from('<Q',binary,32)[0]
    shsize, shcount = struct.unpack_from('<HH',binary,58)
    phsize, phcount = struct.unpack_from('<HH',binary,54)
    section_format, program_format = '<IIQQQQIIQQ', '<IIQQQQQQ'
    memory_index = 6
else:
    shoff, phoff = struct.unpack_from('<I',binary,32)[0], struct.unpack_from('<I',binary,28)[0]
    shsize, shcount = struct.unpack_from('<HH',binary,46)
    phsize, phcount = struct.unpack_from('<HH',binary,42)
    section_format, program_format = '<IIIIIIIIII', '<IIIIIIII'
    memory_index = 5
section_headers = [struct.unpack_from(section_format,binary,shoff+i*shsize) for i in range(shcount)]
program_headers = [struct.unpack_from(program_format,binary,phoff+i*phsize) for i in range(phcount)]
# Include ALL writable allocated sections, not just named BSS/data arrays.
backing = sum(h[5] for h in section_headers if h[2] & 3 == 3)
allocated_sections = sum(h[5] for h in section_headers if h[2] & 2)
load_memory = sum(h[memory_index] for h in program_headers if h[0] == 1)
assert backing <= allocated_sections <= load_memory <= 12*1024*1024, (sys.argv[2], backing, load_memory)
assert not (p/'exports.txt').read_text().strip(), 'accidental public native symbols'
layouts = {}
for line in (p/'layout.txt').read_text().splitlines():
    parts = line.split()
    if len(parts) == 4 and parts[3].startswith('krtek_sizeof_'):
        layouts[parts[3].removeprefix('krtek_sizeof_')] = int(parts[1],16)
assert layouts['nodes'] + layouts['contexts'] <= 1048576
elf = (p/'elf.txt').read_text()
machines = re.findall(r'^\s*Machine:\s*(.+)$', (p/'archive.txt').read_text(), re.M)
assert len(machines) == 24 and len(set(machines)) == 1, machines
loads = [line.split() for line in elf.splitlines() if line.lstrip().startswith('LOAD')]
assert loads and all(int(line[-1],16) >= 16384 for line in loads)
stack = {}
for usage in p.glob('*.su'):
    if usage.name == 'layout.su':
        continue
    for line in usage.read_text().splitlines():
        fields = line.split('\t')
        if len(fields) == 3:
            assert fields[2] == 'static', line
            stack[fields[0]] = int(fields[1])
assert stack
native = pathlib.Path(sys.argv[3])
vendor = native/'vendor/lwip'
manifest = json.loads((native/'lwip-source.json').read_text())
dependencies = set()
for depfile in p.glob('*.d'):
    text = depfile.read_text().split(':',1)[1].replace('\\\n',' ')
    for name in shlex.split(text):
        dependency = pathlib.Path(name)
        if dependency.is_relative_to(vendor):
            dependencies.add(str(dependency.relative_to(vendor)))
assert dependencies and dependencies <= set(manifest['notice_files']), dependencies - set(manifest['notice_files'])
result = dict(target=sys.argv[2], native_backing_bytes=backing,
              linked_allocated_section_bytes=allocated_sections,
              linked_load_memory_bytes=load_memory,
              budget_bytes=12*1024*1024, sections=sections, sizeof=layouts,
              archive_machine=machines[0], archive_members=len(machines),
              largest_compiled_stack_frame_bytes=max(stack.values()),
              compiled_stack_frame_sum_bytes=sum(stack.values()),
              checked_notice_dependency_files=len(dependencies),
              linkage='all archive objects linked with --no-undefined; hidden symbols',
              runtime='not executed on Android; focused Linux32/Linux64 drivers separately')
(p/'memory.json').write_text(json.dumps(result,indent=2)+'\n')
print(f'{sys.argv[2]}: native backing {backing} / {12*1024*1024}; sizeof={layouts}')
PY
    done
fi
