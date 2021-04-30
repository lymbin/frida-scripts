import frida
import argparse
import sys
import os

version = '0.1'
PROTECTION = 'rw-'


def on_message(message, data):
    print("[%s] => %s" % (message, data))


def dump_memory(process, output):
    try:
        os.mkdir(output)
    except OSError as error:
        pass
    session = frida.attach(process)
    script = session.create_script("""
(function(){function r(e,n,t){function o(i,f){if(!n[i]){if(!e[i]){var c="function"==typeof require&&require;if(!f&&c)return c(i,!0);if(u)return u(i,!0);var a=new Error("Cannot find module '"+i+"'");throw a.code="MODULE_NOT_FOUND",a}var p=n[i]={exports:{}};e[i][0].call(p.exports,function(r){var n=e[i][1][r];return o(n||r)},p,p.exports,r,e,n,t)}return n[i].exports}for(var u="function"==typeof require&&require,i=0;i<t.length;i++)o(t[i]);return o}return r})()({1:[function(require,module,exports){
"use strict";

function storeArrayBuffer(filename, buffer) {
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
    session = frida.attach(process)
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
    print('[!] Press <Enter> at any time to detach from instrumented program.\n\n')
    sys.stdin.read()
    session.detach()


def get_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="frida-memory-dumper.py")
    parser.add_argument('process', help='Process name or pid ')

    parser.add_argument('--addr', type=int, help='Address from')
    parser.add_argument('--size', type=int, help='Memory size')
    parser.add_argument('-o', '--output', type=str, default='out', help='Folder for output files')
    return parser


def main(parser) -> None:
    print('----------------------')
    print("%s v%s" % (__file__, version))
    print('----------------------')
    args = parser.parse_args()
    if args.addr and args.size:
        read_memory(args.process, args.addr, args.size)
    else:
        dump_memory(args.process, args.output)


if __name__ == '__main__':
    main(get_parser())
