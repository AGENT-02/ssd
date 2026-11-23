// ---------------------------------------------------------------------------
// NinjaBypass — self-contained license bypass for NinjaGate-protected apps
// (8 Ball Pool 56.34.0 / com.ninja.engine.ios). No substrate/Logos at link time.
//
// Verified against the real binary:
//   __DATA+0x110  uint8_t _gLicensed   (hint scores 11/13)
//   __DATA+0x118  double  _gLicenseExpiry
//   __DATA+0x120  double  _gNextValidation
//   __TEXT+0x8034 _njBootstrap  stp x28,x30,[sp,#-0x40]!
//   __TEXT+0xad74 _njCheck      stp x28,x30,[sp,#-0x40]!
//
// Load path for injected builds:
//   LC_LOAD_DYLIB @executable_path/Frameworks/libNinjaBypass.dylib
//
// Debug output: Documents/nj.log in the app container + NSLog.
// ---------------------------------------------------------------------------

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <objc/runtime.h>
#import <objc/message.h>
#import <mach-o/dyld.h>
#import <mach-o/loader.h>
#import <mach/mach.h>
#import <dlfcn.h>
#import <time.h>
#import <unistd.h>
#import <string.h>
#import <stdarg.h>

#define NJ_DEBUG 1

// Layout inside __DATA. Deltas are fixed; the base is discovered and validated.
#define NJ_D_LICENSED 0
#define NJ_D_EXPIRY   8
#define NJ_D_NEXT     16

// __TEXT hints, validated against the instruction at the target before hooking.
#define NJ_OFF_BOOTSTRAP 0x8034
#define NJ_OFF_CHECK     0xad74

#define NJ_FAR_SECONDS 315360000.0   // +10 years

#pragma clang diagnostic ignored "-Warc-performSelector-leaks"

// Forward declarations: njScanClasses references these before their definitions.
static void njGateWillAppear(id self, SEL sel, BOOL animated);
static void njGateDidAppear(id self, SEL sel, BOOL animated);
static void njTryLeaveGate(UIViewController *vc, int attempt);

static uint8_t  *gState = NULL;      // points at _gLicensed
static BOOL      gPatched = NO;
static dispatch_source_t gTimer = NULL;

static NSMutableDictionary *gOrigIMPs = nil;
static NSMutableSet *gDone = nil;

// ------------------------------- logging -----------------------------------

static void njLog(NSString *fmt, ...) {
#if NJ_DEBUG
    va_list ap; va_start(ap, fmt);
    NSString *msg = [[NSString alloc] initWithFormat:fmt arguments:ap];
    va_end(ap);
    NSLog(@"[NinjaBypass] %@", msg);

    NSString *dir = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES attributes:nil error:NULL];
    NSString *p = [dir stringByAppendingPathComponent:@"nj.log"];
    if (![[NSFileManager defaultManager] fileExistsAtPath:p])
        [@"" writeToFile:p atomically:YES encoding:NSUTF8StringEncoding error:NULL];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:p];
    if (fh) {
        @try { [fh seekToEndOfFile];
                [fh writeData:[[msg stringByAppendingString:@"\n"]
                               dataUsingEncoding:NSUTF8StringEncoding]]; }
        @catch (__unused NSException *e) {}
        [fh closeFile];
    }
#endif
}

// ------------------------------ PAC helpers --------------------------------

#if __has_feature(ptrauth_calls)
static inline void *njSign(void *p) {
    return __builtin_ptrauth_sign_unauthenticated(p, ptrauth_key_function_pointer, 0);
}
#define NJ_CALL(fp) ((__typeof__(fp))njSign((void *)(fp)))
#else
#define NJ_CALL(fp) (fp)
#endif

// --------------------------- Mach-O navigation -----------------------------

static uint8_t *njSeg(const struct mach_header_64 *mh, const char *name, size_t *out) {
    if (!mh || mh->magic != MH_MAGIC_64) return NULL;
    uint8_t *p = (uint8_t *)(mh + 1);
    for (uint32_t i = 0; i < mh->ncmds; i++) {
        struct load_command *lc = (struct load_command *)p;
        if (lc->cmdsize < sizeof(struct load_command)) return NULL;
        if (lc->cmd == LC_SEGMENT_64) {
            struct segment_command_64 *sc = (struct segment_command_64 *)lc;
            if (strncmp(sc->segname, name, 16) == 0 && sc->vmsize) {
                if (out) *out = (size_t)sc->vmsize;
                return (uint8_t *)((uintptr_t)mh + sc->vmaddr);
            }
        }
        p += lc->cmdsize;
    }
    return NULL;
}

static const char *njImagePathForHeader(const struct mach_header *target) {
    for (uint32_t i = 0; i < _dyld_image_count(); i++)
        if (_dyld_get_image_header(i) == target) return _dyld_get_image_name(i);
    return NULL;
}

static BOOL njMakeWritable(void *addr, size_t len) {
    vm_address_t start = (vm_address_t)addr & ~(vm_page_size - 1);
    vm_address_t end   = ((vm_address_t)addr + len + vm_page_size - 1) & ~(vm_page_size - 1);
    kern_return_t kr = vm_protect(mach_task_self(), start, end - start, false,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) njLog(@"vm_protect failed at %p: %d", addr, kr);
    return kr == KERN_SUCCESS;
}

// --------------------------- state discovery -------------------------------

static BOOL njPlausibleTS(double v) {
    return v == 0.0 || (v > 1.0e9 && v < 4.2e9);   // 2001..2103
}

static NSInteger njScore(const uint8_t *seg, size_t i) {
    uint8_t lic = seg[i];
    if (lic > 1) return -1;
    double e = *(const double *)(seg + i + NJ_D_EXPIRY);
    double n = *(const double *)(seg + i + NJ_D_NEXT);
    if (!njPlausibleTS(e) || !njPlausibleTS(n)) return -1;

    NSInteger s = 4;
    BOOL pad = YES;
    for (int k = 1; k < 8; k++) if (seg[i + k]) { pad = NO; break; }
    if (pad) s += 3;                                  // padding before the double
    if (lic == 0) s += 2;                             // unactivated is the usual state
    if (e == n) s += 2;                               // both written together
    double now = (double)time(NULL);
    if (e > now && n > now) s += 2;                   // both in the future
    return s;
}

// Scan a data segment 8-byte aligned; return the best candidate or NULL.
static uint8_t *njFindState(uint8_t *seg, size_t size, size_t hint) {
    if (!seg || size < 0x200) return NULL;

    // Known-good hint first. Verified score on 56.34.0 is 11.
    if (hint + 24 < size && njScore(seg, hint) >= 8) {
        njLog(@"state found at hint +0x%zx", hint);
        return seg + hint;
    }

    uint8_t *best = NULL; NSInteger bestScore = 6;
    for (size_t i = 0; i + 24 < size; i += 8) {
        NSInteger s = njScore(seg, i);
        if (s > bestScore) { bestScore = s; best = seg + i; }
    }
    if (best) njLog(@"state found by scan at +0x%zx (score %ld)",
                    (size_t)(best - seg), (long)bestScore);
    return best;
}

static void njForce(void) {
    if (!gState) return;
    njMakeWritable(gState, 24);
    double far = (double)time(NULL) + NJ_FAR_SECONDS;
    gState[NJ_D_LICENSED] = 1;
    *(double *)(gState + NJ_D_EXPIRY) = far;
    *(double *)(gState + NJ_D_NEXT)   = far;
}

// ---------------------------- license file ---------------------------------

static void njWriteLicense(void) {
    double far = (double)time(NULL) + NJ_FAR_SECONDS;
    NSString *body = [NSString stringWithFormat:@"OK %llu", (uint64_t)(far * 1000.0)];
    NSString *home = NSHomeDirectory();
    NSFileManager *fm = [NSFileManager defaultManager];

    // Names confirmed from strings in the framework.
    NSArray *rels = @[ @"Documents/ninja_license.txt",
                       @"Documents/ninja_console_v3_license.txt",
                       @"Documents/hulk_console_v2_license.txt",
                       @"Documents/ninjagate_license.txt",
                       @"Library/Application Support/ninja_license.txt" ];

    for (NSString *rel in rels) {
        NSString *path = [home stringByAppendingPathComponent:rel];
        [fm createDirectoryAtPath:[path stringByDeletingLastPathComponent]
      withIntermediateDirectories:YES attributes:nil error:NULL];
        NSError *err = nil;
        if (![body writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:&err])
            njLog(@"write failed %@: %@", rel, err.localizedDescription);
    }

    // Device fingerprint: only seed it if the gate has never made one.
    NSString *dev = [home stringByAppendingPathComponent:@"Documents/ninja_device.txt"];
    if (![fm fileExistsAtPath:dev]) {
        [[[NSUUID UUID] UUIDString] writeToFile:dev atomically:YES
                                       encoding:NSUTF8StringEncoding error:NULL];
        njLog(@"seeded ninja_device.txt");
    }
    njLog(@"license files written");
}

// ------------------------- optional substrate hooks ------------------------

typedef void (*MSHookFunction_t)(void *, void *, void **);
static MSHookFunction_t njMSHookFunction(void) {
    static MSHookFunction_t fn = NULL;
    if (fn) return fn;
    fn = (MSHookFunction_t)dlsym(RTLD_DEFAULT, "MSHookFunction");
    if (!fn) {
        const char *paths[] = { "/var/jb/usr/lib/libsubstrate.dylib",
                                "/usr/lib/libsubstrate.dylib",
                                "/var/jb/usr/lib/libellekit.dylib",
                                "/usr/lib/libellekit.dylib" };
        for (int i = 0; i < 4 && !fn; i++) {
            void *h = dlopen(paths[i], RTLD_NOW);
            if (h) fn = (MSHookFunction_t)dlsym(h, "MSHookFunction");
        }
    }
    return fn;
}

static BOOL (*orig_bootstrap)(void *);
static BOOL (*orig_check)(void *);

static BOOL njBootstrapHook(void *ctx) {
    njLog(@"bootstrap hook");
    njWriteLicense();
    njForce();
    if (orig_bootstrap) NJ_CALL(orig_bootstrap)(ctx);
    njForce();
    return YES;
}

static BOOL njCheckHook(void *ctx) {
    njLog(@"check hook");
    njForce();
    if (orig_check) NJ_CALL(orig_check)(ctx);   // keep side effects
    njForce();                                  // in case it reset the flags
    return YES;
}

// STP pre-index 64-bit keeps bits 31..22 fixed at 0xA98; imm7 occupies 21..15.
static BOOL njPlausiblePrologue(uint32_t insn) {
    return insn == 0xD503233F                      // pacibsp
        || (insn & 0xFFC00000) == 0xA9800000;      // stp xN,xZ,[sp,#-imm]!
}

static void njHookText(const struct mach_header_64 *mh) {
    MSHookFunction_t hook = njMSHookFunction();
    if (!hook) { njLog(@"no substrate at runtime - C hooks skipped"); return; }

    size_t sz = 0;
    uint8_t *text = njSeg(mh, "__TEXT", &sz);
    if (!text || sz < NJ_OFF_CHECK + 4) { njLog(@"__TEXT too small"); return; }

    struct { size_t off; void *rep; void **orig; const char *nm; } items[] = {
        { NJ_OFF_BOOTSTRAP, (void *)njBootstrapHook, (void **)&orig_bootstrap, "_njBootstrap" },
        { NJ_OFF_CHECK,     (void *)njCheckHook,     (void **)&orig_check,     "_njCheck" },
    };
    for (int i = 0; i < 2; i++) {
        uint32_t insn = *(uint32_t *)(text + items[i].off);
        if (!njPlausiblePrologue(insn)) {
            njLog(@"%@ at 0x%zx looks wrong (0x%08x) - skipped",
                  @(items[i].nm), items[i].off, insn);
            continue;
        }
        njMakeWritable(text + items[i].off, 16);
        hook(text + items[i].off, items[i].rep, items[i].orig);
        njLog(@"hooked %@", @(items[i].nm));
    }
}

// --------------------------- ObjC decision hooks ---------------------------

static BOOL njBoolish(const char *enc) {
    if (!enc || !*enc) return NO;
    switch (enc[0]) {
        case 'c': case 'B': case 'i': case 'I':
        case 's': case 'S': case 'q': case 'Q':
        case 'l': case 'L': return YES;
        default: return NO;
    }
}

static BOOL njRelevantSel(const char *s) {
    if (!s) return NO;
    if (strncmp(s, "set", 3) == 0) return NO;
    if (strncmp(s, "init", 4) == 0) return NO;
    if (strstr(s, "Notification")) return NO;
    static const char *keys[] = { "licen", "activ", "valid", "gate", "purchas",
                                  "premium", "subscri", "trial", "expir", "unlock",
                                  "isPro", "hasPro", "entitle", "paid", "owned" };
    for (unsigned i = 0; i < sizeof(keys)/sizeof(*keys); i++)
        if (strcasestr(s, keys[i])) return YES;
    return NO;
}

static BOOL njYes0(id self, SEL _c)                     { return YES; }
static BOOL njYes1(id self, SEL _c, id a)               { return YES; }
static BOOL njYes2(id self, SEL _c, id a, id b)         { return YES; }
static BOOL njYes3(id self, SEL _c, id a, id b, id c)   { return YES; }

static void njSwizzle(Class cls, SEL sel, IMP rep) {
    Method m = class_getInstanceMethod(cls, sel);
    if (!m) return;
    NSString *key = [NSString stringWithFormat:@"%p:%s", cls, sel_getName(sel)];
    if ([gDone containsObject:key]) return;
    [gDone addObject:key];
    gOrigIMPs[key] = [NSValue valueWithPointer:(void *)method_getImplementation(m)];
    method_setImplementation(m, rep);
    njLog(@"swizzled -[%s %s] %s", class_getName(cls), sel_getName(sel),
          method_getTypeEncoding(m));
}

static IMP njOrigIMP(id self, SEL sel) {
    NSString *key = [NSString stringWithFormat:@"%p:%s", object_getClass(self), sel_getName(sel)];
    return (IMP)[gOrigIMPs[key] pointerValue];
}

static BOOL njIsVC(Class cls) {
    for (Class c = cls; c; c = class_getSuperclass(c))
        if (c == [UIViewController class]) return YES;
    return NO;
}

static BOOL njIsGateClass(Class cls) {
    const char *n = class_getName(cls);
    return strcasestr(n, "gate") || strcasestr(n, "licen") || strcasestr(n, "activ");
}

static void njScanClasses(void) {
    int n = objc_getClassList(NULL, 0);
    if (n <= 0) return;
    __unsafe_unretained Class *list =
        (__unsafe_unretained Class *)calloc((size_t)n, sizeof(Class));
    if (!list) return;
    n = objc_getClassList(list, n);

    for (int i = 0; i < n; i++) {
        Class cls = list[i];
        const char *img = class_getImageName(cls);
        if (!img || !strstr(img, "NinjaGate.framework/NinjaGate")) continue;

        BOOL gateVC = njIsGateClass(cls) && njIsVC(cls);

        // decision methods: instance + class
        for (int pass = 0; pass < 2; pass++) {
            Class target = pass ? object_getClass(cls) : cls;
            unsigned count = 0;
            Method *ms = class_copyMethodList(target, &count);
            for (unsigned k = 0; k < count; k++) {
                const char *sel = sel_getName(method_getName(ms[k]));
                if (!njRelevantSel(sel) || !njBoolish(method_getTypeEncoding(ms[k]))) continue;
                unsigned args = method_getNumberOfArguments(ms[k]);
                IMP rep = args <= 2 ? (IMP)njYes0
                        : args == 3 ? (IMP)njYes1
                        : args == 4 ? (IMP)njYes2
                                    : (IMP)njYes3;
                njSwizzle(cls, method_getName(ms[k]), rep);
            }
            free(ms);
        }

        if (!gateVC) continue;

        // gate VC lifecycle
        unsigned count = 0;
        Method *ms = class_copyMethodList(cls, &count);
        for (unsigned k = 0; k < count; k++) {
            const char *sel = sel_getName(method_getName(ms[k]));
            if (strcmp(sel, "viewWillAppear:") == 0 || strcmp(sel, "viewDidAppear:") == 0) {
                IMP rep = strcmp(sel, "viewWillAppear:") == 0
                        ? (IMP)njGateWillAppear : (IMP)njGateDidAppear;
                njSwizzle(cls, method_getName(ms[k]), rep);
            }
        }
        free(ms);
    }
    free(list);
}

static void njGateWillAppear(id self, SEL sel, BOOL animated) {
    njForce();
    IMP o = njOrigIMP(self, sel);
    if (o) ((void (*)(id, SEL, BOOL))o)(self, sel, animated);
}

static void njGateDidAppear(id self, SEL sel, BOOL animated) {
    njForce();
    IMP o = njOrigIMP(self, sel);
    if (o) ((void (*)(id, SEL, BOOL))o)(self, sel, animated);
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.2 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        UIViewController *gate = self;
        njTryLeaveGate(gate, 0);
    });
}

static void njTryLeaveGate(UIViewController *vc, int attempt) {
    if (!vc || !gState) return;
    njForce();

    @try {
        if (vc.presentingViewController) {
            [vc dismissViewControllerAnimated:NO completion:nil];
            njLog(@"dismissed gate (attempt %d)", attempt);
            return;
        }

        NSArray *sels = @[ @"continueTapped:", @"continueButtonTapped:", @"onContinue:",
                           @"didContinue", @"dismissGate", @"finish", @"onSuccess",
                           @"unlock", @"activate" ];
        for (NSString *name in sels) {
            SEL s = NSSelectorFromString(name);
            if (![vc respondsToSelector:s]) continue;
            if ([name hasSuffix:@":"]) [vc performSelector:s withObject:vc];
            else [vc performSelector:s];
            njLog(@"called -%@", name);
            return;
        }

        UIWindow *win = vc.view.window;
        if (win && win.rootViewController == vc) {
            NSArray *kids = (NSArray *)[vc valueForKey:@"children"];
            for (UIViewController *c in kids) {
                if (!njIsGateClass(object_getClass(c))) {
                    win.rootViewController = c;
                    njLog(@"promoted child %@ to root", NSStringFromClass(object_getClass(c)));
                    return;
                }
            }
        }
        vc.view.hidden = YES;
        njLog(@"hid gate view (attempt %d)", attempt);
    }
    @catch (NSException *e) {
        njLog(@"leave gate exception: %@", e.reason);
    }

    if (attempt < 4) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(1.5 * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ njTryLeaveGate(vc, attempt + 1); });
    }
}

// ------------------------------- pipeline ----------------------------------

static void njStartTimer(void) {
    if (gTimer) return;
    gTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                    dispatch_get_global_queue(QOS_CLASS_UTILITY, 0));
    if (!gTimer) return;
    dispatch_source_set_timer(gTimer, dispatch_time(DISPATCH_TIME_NOW, 0),
                              1ull * NSEC_PER_SEC, 100ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(gTimer, ^{ njForce(); });
    dispatch_resume(gTimer);
}

static void njPatchImage(const struct mach_header *mh, const char *path) {
    if (gPatched) return;
    const struct mach_header_64 *m64 = (const struct mach_header_64 *)mh;
    if (!m64 || m64->magic != MH_MAGIC_64) return;

    njLog(@"framework at %p (%s)", mh, path);

    // __DATA first: it is writable and holds the mutable globals.
    struct { const char *seg; size_t hint; } cands[] = {
        { "__DATA", 0x110 }, { "__DATA_DIRTY", 0x110 }, { "__DATA_CONST", 0x110 },
        { "__AUTH", 0x110 }, { "__AUTH_CONST", 0x110 },
    };

    uint8_t *found = NULL;
    for (int i = 0; i < 5 && !found; i++) {
        size_t sz = 0;
        uint8_t *seg = njSeg(m64, cands[i].seg, &sz);
        if (!seg) continue;
        njMakeWritable(seg, sz);
        found = njFindState(seg, sz, cands[i].hint);
        if (found) njLog(@"state in %s at +0x%zx", cands[i].seg,
                         (size_t)(found - seg));
    }

    if (!found) { njLog(@"state not found - offsets likely wrong for this build"); return; }
    gState = found;
    gPatched = YES;

    njForce();
    njWriteLicense();
    njHookText(m64);
    njStartTimer();

    // Classes register during framework initialisers; scan a few times.
    for (int i = 0; i < 15; i++) {
        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)((0.5 + i * 0.5) * NSEC_PER_SEC)),
                       dispatch_get_main_queue(), ^{ njScanClasses(); });
    }
}

static void njImageAdded(const struct mach_header *mh, intptr_t slide) {
    const char *path = njImagePathForHeader(mh);
    if (!path || !strstr(path, "NinjaGate.framework/NinjaGate")) return;
    NSString *p = [NSString stringWithUTF8String:path];
    // Deferred: njMSHookFunction dlopens, which can wedge the dyld lock.
    dispatch_async(dispatch_get_global_queue(QOS_CLASS_UTILITY, 0), ^{
        njPatchImage(mh, p.UTF8String);
    });
}

__attribute__((constructor)) static void njInit(void) {
    @autoreleasepool {
        gOrigIMPs = [NSMutableDictionary dictionary];
        gDone = [NSMutableSet set];
        njLog(@"loaded, pid %d", getpid());
        _dyld_register_func_for_add_image(njImageAdded);   // fires for existing too
    }
}
