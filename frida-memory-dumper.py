import frida
import argparse
import sys
import os
import subprocess
import time
import shutil

version = '1.0'
PROTECTION = 'rw-'


def on_message(message, data):
    print("[%s] => %s" % (message, data))


def get_bytes(str):
    result = ''
    q = 0
    for c in str:
        if q != 1:
            result += c.encode("utf-8").hex()
            if q != len(str)-1:
                result += ' '
        else:
            result += '?? '
        q += 1
    return result


def check_proc(process):
    proc1 = subprocess.Popen(['frida-ps'], stdout=subprocess.PIPE)
    proc2 = subprocess.Popen(['grep', '-i', process], stdin=proc1.stdout,
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc1.stdout.close()
    result, err = proc2.communicate()
    return result


def attach(process):
    try:
        session = frida.attach(process)
    except frida.ProcessNotFoundError:
        print('[!] No app running. Trying to spawn.')
        pid = spawn_app(process)
        session = frida.attach(pid)
    return session


def spawn_app(process):
    print('Spawning %s app.' % process)
    pid = frida.spawn(shutil.which(process))
    frida.resume(pid)
    time.sleep(5)
    print('Spawned.')
    return pid


def scan_memory(process, pattern, interactive=False):
    print('Scanning %s as \'%s\' pattern.' % (process, pattern))
    session = attach(process)
    if interactive:
        print('[Interactive] Press Enter to scan...')
        input()
    script = session.create_script("""
        var ranges = Process.enumerateRangesSync({protection: 'r--', coalesce: true});
        var range;
        function processNext(){
            range = ranges.pop();
            if (!range){
                // we are done
                return;
            }
            // due to the lack of blacklisting in Frida, there will be 
            // always an extra match of the given pattern (if found) because
            // the search is done also in the memory owned by Frida.
            Memory.scan(range.base, range.size, '%s', {
                onMatch: function(address, size){
                        console.log('[+] Pattern found at: ' + address.toString());
                        console.log(hexdump(address));
                    }, 
                onError: function(reason){
                        console.log('[!] There was an error scanning memory');
                    }, 
                onComplete: function(){
                        processNext();
                    }
                });
        }
        processNext();
""" % pattern)
    script.on('message', on_message)
    script.load()
    input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
    session.detach()


def dump_memory(process, output, interactive=False):
    print('Dumping %s memory.' % process)
    if not os.path.isabs(output):
        output = os.path.join(os.path.dirname(os.path.realpath(__file__)), output)
    try:
        os.mkdir(output)
    except OSError as error:
        pass
    session = attach(process)
    if interactive:
        print('[Interactive] Press Enter to dump...')
        input()
    script = session.create_script("""
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

function storeArrayBuffer(filename, buffer) {
    console.log(filename);
    var destFileName = new File(filename, "wb");
    destFileName.write(buffer);
    destFileName.flush();
    destFileName.close();
}

rpc.exports = {
    dumpProcessMemory: function dumpProcessMemory(protection) {
        var ranges = Process.enumerateRanges(protection);
        var totalRanges = ranges.length;
        var failedDumps = 0;
        console.log('[BEGIN] Located ' + totalRanges + ' memory ranges matching [' + protection + ']');
        ranges.forEach(function (range) {
            var destFileName = "%s/".concat(range.base, "_dump");
            var arrayBuf;
            try {
                arrayBuf = range.base.readByteArray(range.size);
            } catch (e) {
                failedDumps += 1;
                return;
            }
            if (arrayBuf) {
                storeArrayBuffer(destFileName, arrayBuf);
            }
        });
        var sucessfulDumps = totalRanges - failedDumps;
        console.log("[FINISH] Succesfully dumped ".concat(sucessfulDumps, "/").concat(totalRanges, " ranges."));
    }
};

},{}]},{},[1])""" % output)
    script.on('message', on_message)
    script.load()
    try:
        script.exports.dump_process_memory(PROTECTION)
    except frida.InvalidOperationError:
        print('InvalidOperationError: Process is not running anymore.')
    session.detach()


def read_memory(process, addr, size):
    print('Reading %s memory.' % process)
    session = attach(process)
    script = session.create_script("""
var buf = Memory.readByteArray(ptr('0x%x'), %d);
console.log(hexdump(buf, {
    offset: 0, 
    length: %d, 
    header: true,
    ansi: false
}));
""" % (addr, size, size))
    script.on('message', on_message)
    script.load()
    input('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
    session.detach()


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="frida-memory-dumper.py")
    parser.add_argument('process', help='Process name or pid')

    parser.add_argument('--spawn', action='store_true', help='Spawn app path')
    parser.add_argument('--spawntime', type=int, default=5, help='Spawn time')

    parser.add_argument('--scan', action='store_true', help='Scan memory with pattern')
    parser.add_argument('--dump', action='store_true', help='Dump memory')

    parser.add_argument('--interactive', action='store_true', help='Dump and Scan memory when user want')

    parser.add_argument('--pattern', type=str,  help='Scan Pattern Bytes in form "42 2c ?? 00 4a" ')
    parser.add_argument('--spattern', type=str,  help='Scan Pattern Str')

    parser.add_argument('--addr', type=str, help='Address from')
    parser.add_argument('--size', type=int, help='Memory size')
    parser.add_argument('-o', '--output', type=str, default='out', help='Folder for output files')
    return parser


def main(parser) -> None:
    print('---------------------------')
    print("%s v%s" % (__file__, version))
    print('---------------------------')
    args = parser.parse_args()

    if not args.scan and not args.dump:
        print('No mode selected')
        parser.print_help(sys.stderr)
        sys.exit(1)

    if args.spawn:
        if check_proc(args.process):
            subprocess.run(['frida-kill', args.process], stdout=subprocess.PIPE)
        spawn_app(args.process)

    if args.dump:
        if args.addr and args.size:
            read_memory(args.process, int(args.addr, 16), args.size)
        else:
            dump_memory(args.process, args.output, args.interactive)
    elif args.scan:
        if not args.pattern and not args.spattern:
            print('No scan pattern')
            parser.print_help(sys.stderr)
            sys.exit(1)
        elif args.pattern:
            scan_memory(args.process, args.pattern, args.interactive)
        elif args.spattern:
            spattern = get_bytes(args.spattern)
            print('Pattern is "%s"' % spattern)
            scan_memory(args.process, spattern, args.interactive)


if __name__ == '__main__':
    main(get_parser())
