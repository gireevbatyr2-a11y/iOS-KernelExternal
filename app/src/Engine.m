#import "Engine.h"

static Engine *gEngine = nil;

@implementation Engine

+ (instancetype)shared
{
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        gEngine = [[Engine alloc] init];
    });
    return gEngine;
}

- (NSString *)startKernel
{
    if (self.kernelReady) return nil;
    KEConfig cfg = { .verbose = true };
    int r = keInit(&cfg);
    if (r != KE_OK) {
        if (r == KE_ERR_EXPLOIT_ALREADY_USED) {
            return @"Kernel exploit already used this boot. Reboot the iPhone, then run again.\n(Log: /var/mobile/Documents/kernelexternal.log)";
        }
        return [NSString stringWithFormat:@"keInit failed: %s\n(Log: /var/mobile/Documents/kernelexternal.log)", keErrorString(r)];
    }
    return nil;
}

- (BOOL)kernelReady
{
    return keIsInitialized();
}

- (NSString *)backendName
{
    return [NSString stringWithUTF8String:keActiveBackendName()];
}

- (BOOL)attached
{
    return keAttachedPid() > 0;
}

- (pid_t)attachedPid
{
    return keAttachedPid();
}

- (NSString *)attach:(pid_t)pid
{
    if (!self.kernelReady) {
        NSString *err = [self startKernel];
        if (err) return err;
    }
    kern_return_t kr = keAttach(pid, KE_TFP_FLAG_ZERO_BOTH);
    if (kr != KERN_SUCCESS) {
        return [NSString stringWithFormat:@"attach(%d) failed: mach error %d", pid, kr];
    }
    return nil;
}

- (void)detach
{
    keDetach();
}

- (NSString *)readHex:(uint64_t)addr size:(NSUInteger)size
{
    if (!self.attached) return nil;
    uint8_t buf[64] = { 0 };
    if (size == 0 || size > sizeof(buf)) return nil;
    kern_return_t kr = keReadMem(addr, buf, size);
    if (kr != KERN_SUCCESS) {
        return [NSString stringWithFormat:@"read error %d", kr];
    }
    NSMutableString *hex = [NSMutableString string];
    for (NSUInteger i = 0; i < size; i++) {
        [hex appendFormat:@"%02x", buf[i]];
    }
    return hex;
}

- (NSString *)writeHex:(uint64_t)addr hex:(NSString *)hex
{
    if (!self.attached) return @"not attached";
    if (hex.length == 0 || hex.length % 2 != 0 || hex.length / 2 > 64) {
        return @"hex must be 2..128 hex chars";
    }
    uint8_t buf[64] = { 0 };
    for (NSUInteger i = 0; i < hex.length; i += 2) {
        unsigned int byte;
        if (sscanf([[hex substringWithRange:NSMakeRange(i, 2)] UTF8String], "%2x", &byte) != 1) {
            return @"invalid hex";
        }
        buf[i / 2] = (uint8_t)byte;
    }
    kern_return_t kr = keWriteMem(addr, buf, hex.length / 2);
    if (kr != KERN_SUCCESS) {
        return [NSString stringWithFormat:@"write error %d", kr];
    }
    return nil;
}

- (void)zeroExtmods
{
    if (self.attached) {
        keZeroExtmodOfPid(self.attachedPid);
        keZeroExtmodSelf();
    }
}

@end
