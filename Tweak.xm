// NinjaBypass — license bypass for 8 Ball pool 56.34.0 (com.ninja.engine.ios)
// Targets NinjaGate.framework by address. All offsets verified from the real binary.

#import <Foundation/Foundation.h>
#import <UIKit/UIKit.h>
#import <dispatch/dispatch.h>
#import <objc/runtime.h>
#import <mach-o/dyld.h>
#import <substrate.h>
#import <time.h>
#import <unistd.h>
#import <string.h>

#define NJ_LICENSED   0x14110   // uint8_t  _gLicensed
#define NJ_EXPIRY     0x14118   // double   _gLicenseExpiry
#define NJ_NEXTVAL    0x14120   // double   _gNextValidation
#define NJ_BOOTSTRAP  0x8034    // _njBootstrap (license file loader)
#define NJ_CHECK      0xad74    // _njCheck (network activation)
#define NJ_STATE      0x14000   // __DATA base the offsets are relative to

static uintptr_t gBase = 0;
static void (*orig_njCheck)(void *ctx) = NULL;
static void (*orig_njBootstrap)(void *ctx) = NULL;
static dispatch_source_t gTimer = NULL;
static BOOL gHooked = NO;

static uintptr_t njFindGate(void) {
    uint32_t n = _dyld_image_count();
    for (uint32_t i = 0; i < n; i++) {
        const char *name = _dyld_get_image_name(i);
        if (name && strstr(name, "NinjaGate.framework/NinjaGate"))
            return (uintptr_t)_dyld_get_image_header(i);
    }
    return 0;
}

// The gate's own parser wants "OK " followed by a millisecond epoch in the future.
static void njWriteLicense(void) {
    uint64_t ms = ((uint64_t)time(NULL) + 315360000ULL) * 1000ULL;  // now + 10 years
    NSString *body = [NSString stringWithFormat:@"OK %llu", ms];
    NSString *dir  = [NSHomeDirectory() stringByAppendingPathComponent:@"Documents"];
    NSString *path = [dir stringByAppendingPathComponent:@"ninja_license.txt"];

    [[NSFileManager defaultManager] createDirectoryAtPath:dir
                              withIntermediateDirectories:YES
                                               attributes:nil
                                                    error:NULL];
    [body writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL];
}

static void njForceFlags(void) {
    if (!gBase) return;
    double far = (double)time(NULL) + 315360000.0;

    *(uint8_t *)(gBase + NJ_LICENSED) = 1;
    *(double  *)(gBase + NJ_EXPIRY)   = far;
    *(double  *)(gBase + NJ_NEXTVAL)  = far;
}

// Kill the server round trip so nothing can revoke the local state.
static void njCheckHook(void *ctx) {
    njForceFlags();
}

// Make sure the license file exists *before* the gate's own parser reads it.
static void njBootstrapHook(void *ctx) {
    njWriteLicense();
    njForceFlags();
    if (orig_njBootstrap) orig_njBootstrap(ctx);
}

static void njStartTimer(void) {
    if (gTimer) return;
    gTimer = dispatch_source_create(DISPATCH_SOURCE_TYPE_TIMER, 0, 0,
                                    dispatch_get_global_queue(0, 0));
    if (!gTimer) return;

    dispatch_source_set_timer(gTimer,
                              dispatch_time(DISPATCH_TIME_NOW, 0),
                              500ull * NSEC_PER_MSEC,
                              100ull * NSEC_PER_MSEC);
    dispatch_source_set_event_handler(gTimer, ^{
        njForceFlags();
    });
    dispatch_resume(gTimer);
}

static void njSetup(void) {
    for (int i = 0; i < 200 && !gBase; i++) {
        gBase = njFindGate();
        if (!gBase) usleep(50000);
    }
    if (!gBase) return;

    njWriteLicense();
    njForceFlags();

    if (!gHooked) {
        MSHookFunction((void *)(gBase + NJ_BOOTSTRAP),
                       (void *)njBootstrapHook,
                       (void **)&orig_njBootstrap);
        MSHookFunction((void *)(gBase + NJ_CHECK),
                       (void *)njCheckHook,
                       (void **)&orig_njCheck);
        gHooked = YES;
    }
    njStartTimer();
}

__attribute__((constructor)) static void njInit(void) {
    dispatch_async(dispatch_get_global_queue(0, 0), ^{
        njSetup();
    });
}

// Keep the activation screen out of the way.
@interface NinjaGateController : UIViewController
@end

%hook NinjaGateController

- (void)viewDidAppear:(BOOL)animated {
    %orig;
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (int64_t)(0.4 * NSEC_PER_SEC)),
                   dispatch_get_main_queue(), ^{
        if (self.presentingViewController) {
            [self dismissViewControllerAnimated:NO completion:nil];
        } else {
            self.view.hidden = YES;
        }
    });
}

%end
