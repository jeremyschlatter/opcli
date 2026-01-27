//go:build !test

#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

// C interface for Go
int authenticateTouchID(const char *reason) {
    @autoreleasepool {
        LAContext *context = [[LAContext alloc] init];
        NSString *reasonStr = [NSString stringWithUTF8String:reason];

        dispatch_semaphore_t sema = dispatch_semaphore_create(0);
        __block BOOL success = NO;

        LAPolicy policy = LAPolicyDeviceOwnerAuthenticationWithBiometrics;
        NSError *error = nil;
        if (![context canEvaluatePolicy:policy error:&error]) {
            policy = LAPolicyDeviceOwnerAuthentication;
        }

        [context evaluatePolicy:policy
                localizedReason:reasonStr
                          reply:^(BOOL result, NSError *authError) {
            success = result;
            dispatch_semaphore_signal(sema);
        }];

        dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
        return success ? 0 : 1;
    }
}
