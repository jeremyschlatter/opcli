//go:build !test

// TouchID authentication with an inline context window, matching the unified
// single-window UX of the 1Password desktop app.
//
// We create a custom NSWindow listing the pending op:// refs and embed an
// LAAuthenticationView inside it. The LAAuthenticationView is an NSView
// bundled with the LocalAuthenticationEmbeddedUI framework (macOS 12+) that
// presents biometric UI inline instead of spawning the system SecurityAgent
// dialog. This is what yields the single-card look — no floating LAContext
// modal floats behind/beside our window because there is no system dialog at
// all; the TouchID icon and scan UI are children of our window.
//
// Limitations of LAAuthenticationView:
//   - biometric-only (Touch ID / Watch / companion). If the user has no such
//     hardware, the evaluation fails and we bail to the classic LAContext
//     dispatch-semaphore path (which shows the old system dialog without our
//     window).
//   - the view itself only renders a compact icon; the textual reason has to
//     come from the surrounding window — which is exactly what we want,
//     because that's where the refs list lives.
//
// History of this file:
//   - op-rba (reverted): printed refs to stdout. Polluted pipes.
//   - op-c0e first try (reverted): crammed refs into LAContext reason string.
//     Too cramped, broke CI.
//   - op-c0e second try (PR #7 rev 1): used LAContext standard dialog with a
//     floating NSPanel next to it. Reviewer rejected the two-window look.
//   - this file: LAAuthenticationView embedded in our window. One window.

#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <LocalAuthenticationEmbeddedUI/LocalAuthenticationEmbeddedUI.h>
#import <dispatch/dispatch.h>

@interface OpcliAuthDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, copy) NSString *reason;
@property(nonatomic, copy) NSString *refsText;
@property(nonatomic, assign) BOOL success;
@end

static NSWindow *createAuthWindow(NSString *refsText, LAAuthenticationView *authView) {
    NSScreen *screen = [NSScreen mainScreen] ?: [[NSScreen screens] firstObject];
    NSRect screenFrame = screen ? [screen visibleFrame] : NSMakeRect(0, 0, 1440, 900);

    CGFloat w = 440;
    CGFloat headerH = 32;
    CGFloat refsH = 150;
    CGFloat padding = 16;
    CGFloat authViewHeight = [authView frame].size.height;
    CGFloat h = headerH + refsH + authViewHeight + padding * 4;

    CGFloat x = NSMidX(screenFrame) - w / 2;
    CGFloat y = NSMidY(screenFrame) - h / 2;
    NSRect frame = NSMakeRect(x, y, w, h);

    NSWindow *win = [[NSWindow alloc]
        initWithContentRect:frame
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskFullSizeContentView)
        backing:NSBackingStoreBuffered
        defer:NO];
    [win setTitle:@"opcli"];
    [win setTitlebarAppearsTransparent:YES];
    [win setTitleVisibility:NSWindowTitleHidden];
    [win setMovableByWindowBackground:YES];
    [win setLevel:NSFloatingWindowLevel];
    [win setReleasedWhenClosed:NO];

    NSVisualEffectView *bg = [[NSVisualEffectView alloc] initWithFrame:NSMakeRect(0, 0, w, h)];
    [bg setMaterial:NSVisualEffectMaterialHUDWindow];
    [bg setBlendingMode:NSVisualEffectBlendingModeBehindWindow];
    [bg setState:NSVisualEffectStateActive];
    [bg setWantsLayer:YES];
    [[bg layer] setCornerRadius:12];
    [win setContentView:bg];

    CGFloat cursorY = h - padding;

    NSTextField *header = [NSTextField labelWithString:@"Touch ID required to read secrets"];
    [header setFont:[NSFont systemFontOfSize:13 weight:NSFontWeightSemibold]];
    [header setTextColor:[NSColor labelColor]];
    [header setAlignment:NSTextAlignmentCenter];
    cursorY -= headerH;
    [header setFrame:NSMakeRect(padding, cursorY, w - padding * 2, headerH)];
    [bg addSubview:header];

    cursorY -= padding;

    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(padding, cursorY - refsH, w - padding * 2, refsH)];
    [scroll setHasVerticalScroller:YES];
    [scroll setAutohidesScrollers:YES];
    [scroll setBorderType:NSNoBorder];
    [scroll setDrawsBackground:NO];

    NSSize contentSize = [scroll contentSize];
    NSTextView *textView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, contentSize.width, contentSize.height)];
    [textView setEditable:NO];
    [textView setSelectable:YES];
    [textView setDrawsBackground:NO];
    [textView setFont:[NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular]];
    [textView setTextColor:[NSColor labelColor]];
    [textView setTextContainerInset:NSMakeSize(4, 4)];
    [textView setMinSize:NSMakeSize(0, contentSize.height)];
    [textView setMaxSize:NSMakeSize(FLT_MAX, FLT_MAX)];
    [textView setVerticallyResizable:YES];
    [textView setHorizontallyResizable:NO];
    [[textView textContainer] setWidthTracksTextView:YES];
    [textView setString:refsText];
    [scroll setDocumentView:textView];
    [bg addSubview:scroll];

    cursorY -= refsH + padding;

    NSRect avFrame = [authView frame];
    CGFloat avX = (w - avFrame.size.width) / 2;
    [authView setFrame:NSMakeRect(avX, cursorY - avFrame.size.height, avFrame.size.width, avFrame.size.height)];
    [bg addSubview:authView];

    return win;
}

@implementation OpcliAuthDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    LAContext *context = [[LAContext alloc] init];

    // LAAuthenticationView only supports biometric-ish policies. If no
    // biometrics are available, fall back to the classic alert flow — it
    // won't look unified, but it's still functional.
    NSError *canErr = nil;
    BOOL canBiometric = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                                             error:&canErr];
    if (!canBiometric) {
        [context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                localizedReason:self.reason
                          reply:^(BOOL result, NSError *authError) {
            self.success = result;
            dispatch_async(dispatch_get_main_queue(), ^{
                [NSApp stop:nil];
                NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                                   location:NSZeroPoint
                                              modifierFlags:0 timestamp:0
                                               windowNumber:0 context:nil
                                                    subtype:0 data1:0 data2:0];
                [NSApp postEvent:wake atStart:YES];
            });
        }];
        return;
    }

    LAAuthenticationView *authView = [[LAAuthenticationView alloc] initWithContext:context];
    NSWindow *authWindow = createAuthWindow(self.refsText, authView);
    [authWindow makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];

    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
            localizedReason:self.reason
                      reply:^(BOOL result, NSError *authError) {
        self.success = result;
        dispatch_async(dispatch_get_main_queue(), ^{
            [authWindow orderOut:nil];
            [authWindow close];
            [NSApp stop:nil];
            NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                               location:NSZeroPoint
                                          modifierFlags:0 timestamp:0
                                           windowNumber:0 context:nil
                                                subtype:0 data1:0 data2:0];
            [NSApp postEvent:wake atStart:YES];
        });
    }];
}
@end

// C interface for Go.
// If refsText is non-NULL and non-empty, an inline authentication window is
// shown listing the refs. Otherwise, only the standard system prompt appears.
int authenticateTouchID(const char *reason, const char *refsText) {
    @autoreleasepool {
        NSString *reasonStr = [NSString stringWithUTF8String:reason];
        BOOL showWindow = (refsText != NULL && refsText[0] != '\0');

        if (!showWindow) {
            LAContext *context = [[LAContext alloc] init];
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

        [NSApplication sharedApplication];
        [NSApp setActivationPolicy:NSApplicationActivationPolicyRegular];

        OpcliAuthDelegate *delegate = [[OpcliAuthDelegate alloc] init];
        delegate.reason = reasonStr;
        delegate.refsText = [NSString stringWithUTF8String:refsText];
        [NSApp setDelegate:delegate];
        [NSApp run];
        return delegate.success ? 0 : 1;
    }
}
