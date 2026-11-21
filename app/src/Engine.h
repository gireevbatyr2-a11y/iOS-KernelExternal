#import <Foundation/Foundation.h>
#import <KernelExternal.h>

@interface Engine : NSObject
+ (instancetype)shared;
@property (nonatomic, readonly) BOOL kernelReady;
@property (nonatomic, readonly) NSString *backendName;
@property (nonatomic, readonly) BOOL attached;
@property (nonatomic, readonly) pid_t attachedPid;

- (NSString *)startKernel;
- (NSString *)attach:(pid_t)pid;
- (void)detach;
- (NSString *)readHex:(uint64_t)addr size:(NSUInteger)size;
- (NSString *)writeHex:(uint64_t)addr hex:(NSString *)hex;
- (void)zeroExtmods;
@end
