//go:build !test

#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <dispatch/dispatch.h>

// Build a context window that floats above the terminal showing which refs are
// being authenticated for. Same pattern as 1Password / pinentry-mac / ssh-askpass:
// we show our own informational UI, then the system TouchID dialog appears on top.
static NSWindow *createContextWindow(NSString *refsText) {
    NSRect frame = NSMakeRect(0, 0, 520, 260);
    NSWindow *panel = [[NSPanel alloc]
        initWithContentRect:frame
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskUtilityWindow)
        backing:NSBackingStoreBuffered
        defer:NO];
    [panel setTitle:@"opcli"];
    [panel setLevel:NSFloatingWindowLevel];
    [panel setReleasedWhenClosed:NO];
    [panel setHidesOnDeactivate:NO];
    [panel center];

    NSView *content = [panel contentView];
    CGFloat w = frame.size.width;
    CGFloat h = frame.size.height;

    NSTextField *header = [NSTextField labelWithString:@"Touch ID required to read secrets:"];
    [header setFont:[NSFont boldSystemFontOfSize:13]];
    [header setFrame:NSMakeRect(20, h - 40, w - 40, 20)];
    [content addSubview:header];

    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(20, 50, w - 40, h - 100)];
    [scroll setHasVerticalScroller:YES];
    [scroll setAutohidesScrollers:YES];
    [scroll setBorderType:NSBezelBorder];
    [scroll setDrawsBackground:YES];

    NSSize contentSize = [scroll contentSize];
    NSTextView *textView = [[NSTextView alloc] initWithFrame:NSMakeRect(0, 0, contentSize.width, contentSize.height)];
    [textView setEditable:NO];
    [textView setSelectable:YES];
    [textView setFont:[NSFont userFixedPitchFontOfSize:11]];
    [textView setTextContainerInset:NSMakeSize(8, 8)];
    [textView setMinSize:NSMakeSize(0, contentSize.height)];
    [textView setMaxSize:NSMakeSize(FLT_MAX, FLT_MAX)];
    [textView setVerticallyResizable:YES];
    [textView setHorizontallyResizable:NO];
    [[textView textContainer] setWidthTracksTextView:YES];
    [textView setString:refsText];
    [scroll setDocumentView:textView];
    [content addSubview:scroll];

    NSTextField *footer = [NSTextField labelWithString:@"Touch the sensor to continue, or cancel to abort."];
    [footer setFont:[NSFont systemFontOfSize:11]];
    [footer setTextColor:[NSColor secondaryLabelColor]];
    [footer setFrame:NSMakeRect(20, 20, w - 40, 18)];
    [content addSubview:footer];

    return panel;
}

// C interface for Go.
// If refsText is non-NULL and non-empty, a context window is shown alongside
// the system TouchID prompt. Otherwise, only the system prompt appears.
int authenticateTouchID(const char *reason, const char *refsText) {
    @autoreleasepool {
        NSString *reasonStr = [NSString stringWithUTF8String:reason];
        BOOL showWindow = (refsText != NULL && refsText[0] != '\0');

        NSWindow *ctxWindow = nil;
        if (showWindow) {
            // Initializing NSApp lets us create and display windows. We run as
            // an accessory (no dock icon, no menu bar) since opcli is a CLI.
            [NSApplication sharedApplication];
            [NSApp setActivationPolicy:NSApplicationActivationPolicyAccessory];

            NSString *refsStr = [NSString stringWithUTF8String:refsText];
            ctxWindow = createContextWindow(refsStr);
            [ctxWindow makeKeyAndOrderFront:nil];
            [NSApp activateIgnoringOtherApps:YES];

            // Pump the run loop briefly so the window paints before TouchID appears.
            for (int i = 0; i < 5; i++) {
                CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.01, true);
            }
        }

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

        if (ctxWindow != nil) {
            // Drive the run loop so the context window keeps rendering while
            // we wait for the async LAContext reply.
            while (dispatch_semaphore_wait(sema, DISPATCH_TIME_NOW) != 0) {
                @autoreleasepool {
                    CFRunLoopRunInMode(kCFRunLoopDefaultMode, 0.05, true);
                }
            }
            [ctxWindow orderOut:nil];
            [ctxWindow close];
        } else {
            dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);
        }

        return success ? 0 : 1;
    }
}
