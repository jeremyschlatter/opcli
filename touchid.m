//go:build !test

// TouchID authentication with an inline context window.
//
// We render a single NSWindow containing:
//   - title ("opcli access requested") + subtitle ("request to read N secrets")
//   - a scrollable list of op:// refs grouped by "[account:]vault" header
//     (each vault's refs in an inner scroll view capped at ~8 visible rows so
//     very long lists don't push the auth button off-screen)
//   - an LAAuthenticationView (macOS 12+, biometric UI rendered inline —
//     no separate SecurityAgent modal) with an "Authorize with Touch ID"
//     label
//   - a Cancel button
//
// Grouped ref payload is passed from Go as JSON, shape:
//   [{"vault":"Employee","refs":["item/field", ...]}, ...]
//
// Fallback: if biometrics aren't available (no Touch ID hardware or accessory
// not paired), the inline-window path is skipped entirely and we use the
// classic LAContext.evaluatePolicy dispatch-semaphore flow — no custom
// window, unstyled, but functional.

#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <LocalAuthenticationEmbeddedUI/LocalAuthenticationEmbeddedUI.h>
#import <dispatch/dispatch.h>

// Flipped NSView: y grows downward. Simplifies top-down layout math inside
// the grouped refs scroll view (default Cocoa is bottom-up).
@interface OpcliFlippedView : NSView
@end
@implementation OpcliFlippedView
- (BOOL)isFlipped { return YES; }
@end

@interface OpcliAuthDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, copy)   NSString  *reason;
@property(nonatomic, copy)   NSString  *refsJSON;
@property(nonatomic, strong) LAContext *context;
@property(nonatomic, strong) NSWindow  *window;
@property(nonatomic, assign) BOOL       success;
- (void)cancelClicked:(id)sender;
@end

// Build the grouped refs list as a single flipped NSView suitable for
// hosting inside an NSScrollView. Each vault becomes a header + an inner
// scroll view containing its refs (capped to ~8 visible rows so very long
// lists don't push the auth button off-screen). The host is flipped so y
// grows downward — simpler top-down layout math.
static NSView *buildGroupedRefsList(NSArray *groups, CGFloat width) {
    CGFloat rowH = 17;   // matches monospace 11pt line height with a little breathing room
    CGFloat innerPad = 6;
    CGFloat innerMaxRows = 8;
    CGFloat headerH = 20;
    CGFloat groupSpacing = 14;
    CGFloat sideInset = 4;
    CGFloat headerToRefsGap = 4;

    NSFont *refFont = [NSFont monospacedSystemFontOfSize:11 weight:NSFontWeightRegular];
    NSFont *headerFont = [NSFont systemFontOfSize:12 weight:NSFontWeightSemibold];

    CGFloat contentWidth = width - sideInset * 2;

    // First pass: compute per-section and total heights.
    NSMutableArray *plans = [NSMutableArray array];
    CGFloat totalHeight = 0;
    for (NSDictionary *g in groups) {
        NSArray<NSString *> *refs = g[@"refs"] ?: @[];
        CGFloat innerContent = MAX(rowH, refs.count * rowH) + innerPad * 2;
        CGFloat innerH = MIN(innerContent, innerMaxRows * rowH + innerPad * 2);
        CGFloat sectionH = headerH + headerToRefsGap + innerH;
        [plans addObject:@{@"vault": g[@"vault"] ?: @"",
                           @"refs":  refs,
                           @"innerH": @(innerH),
                           @"sectionH": @(sectionH)}];
        totalHeight += sectionH + groupSpacing;
    }
    if (totalHeight > 0) totalHeight -= groupSpacing;

    OpcliFlippedView *host = [[OpcliFlippedView alloc] initWithFrame:
        NSMakeRect(0, 0, width, totalHeight)];

    // Second pass: lay out top-down (flipped coords).
    CGFloat y = 0;
    for (NSDictionary *plan in plans) {
        NSTextField *header = [NSTextField labelWithString:
            [NSString stringWithFormat:@"# %@", plan[@"vault"]]];
        [header setFont:headerFont];
        [header setTextColor:[NSColor labelColor]];
        [header setFrame:NSMakeRect(sideInset, y, contentWidth, headerH)];
        [host addSubview:header];
        y += headerH + headerToRefsGap;

        CGFloat innerH = [plan[@"innerH"] doubleValue];
        NSScrollView *innerScroll = [[NSScrollView alloc] initWithFrame:
            NSMakeRect(sideInset, y, contentWidth, innerH)];
        [innerScroll setHasVerticalScroller:YES];
        // Keep the scroller visible even when not scrolling, so the user can
        // see there are more refs than fit. Legacy style always draws the
        // track — overlay style fades out.
        [innerScroll setAutohidesScrollers:NO];
        [innerScroll setScrollerStyle:NSScrollerStyleLegacy];
        [innerScroll setBorderType:NSNoBorder];
        [innerScroll setDrawsBackground:NO];
        [innerScroll setTranslatesAutoresizingMaskIntoConstraints:YES];

        NSSize innerContentSize = [innerScroll contentSize];
        NSArray *refs = plan[@"refs"];
        NSMutableAttributedString *refsAttr = [[NSMutableAttributedString alloc] init];
        for (NSUInteger i = 0; i < refs.count; i++) {
            if (i > 0) {
                [refsAttr appendAttributedString:[[NSAttributedString alloc]
                    initWithString:@"\n"]];
            }
            [refsAttr appendAttributedString:[[NSAttributedString alloc]
                initWithString:refs[i]
                attributes:@{NSFontAttributeName: refFont,
                             NSForegroundColorAttributeName: [NSColor labelColor]}]];
        }
        CGFloat docH = MAX(innerContentSize.height, refs.count * rowH + innerPad * 2);
        NSTextView *tv = [[NSTextView alloc] initWithFrame:
            NSMakeRect(0, 0, innerContentSize.width, docH)];
        [tv setEditable:NO];
        [tv setSelectable:YES];
        [tv setDrawsBackground:NO];
        [tv setTextContainerInset:NSMakeSize(innerPad, innerPad)];
        [tv setMinSize:NSMakeSize(0, 0)];
        [tv setMaxSize:NSMakeSize(FLT_MAX, FLT_MAX)];
        [tv setVerticallyResizable:YES];
        [tv setHorizontallyResizable:NO];
        [[tv textContainer] setWidthTracksTextView:YES];
        [[tv textStorage] setAttributedString:refsAttr];
        [innerScroll setDocumentView:tv];
        [host addSubview:innerScroll];
        y += innerH + groupSpacing;
    }

    return host;
}

// Construct the authorization window and install authView as the biometric
// indicator. authView is typically an LAAuthenticationView already paired
// with the LAContext that will be evaluated.
static NSWindow *buildAuthWindow(NSString *refsJSON, NSView *authView,
                                 NSInteger secretCount, id cancelTarget) {
    NSData *data = [refsJSON dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *groups = [NSJSONSerialization JSONObjectWithData:data
                                                      options:0
                                                        error:nil];
    if (![groups isKindOfClass:[NSArray class]]) groups = @[];

    NSScreen *screen = [NSScreen mainScreen] ?: [[NSScreen screens] firstObject];
    NSRect screenFrame = screen ? [screen visibleFrame] : NSMakeRect(0, 0, 1440, 900);

    CGFloat w = 460;
    CGFloat h = 480;
    NSRect frame = NSMakeRect(NSMidX(screenFrame) - w / 2,
                              NSMidY(screenFrame) - h / 2,
                              w, h);

    NSWindow *win = [[NSWindow alloc] initWithContentRect:frame
        styleMask:(NSWindowStyleMaskTitled | NSWindowStyleMaskFullSizeContentView)
        backing:NSBackingStoreBuffered
        defer:NO];
    [win setTitle:@"opcli"];
    [win setTitlebarAppearsTransparent:YES];
    [win setTitleVisibility:NSWindowTitleHidden];
    [win setMovableByWindowBackground:YES];
    [win setLevel:NSFloatingWindowLevel];
    [win setReleasedWhenClosed:NO];
    // Force dark appearance so the dialog looks consistent regardless of
    // system Light/Dark mode — matches 1Password's own auth dialog chrome.
    [win setAppearance:[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua]];

    NSVisualEffectView *bg = [[NSVisualEffectView alloc] initWithFrame:NSMakeRect(0, 0, w, h)];
    [bg setMaterial:NSVisualEffectMaterialHUDWindow];
    [bg setBlendingMode:NSVisualEffectBlendingModeBehindWindow];
    [bg setState:NSVisualEffectStateActive];
    [bg setWantsLayer:YES];
    [[bg layer] setCornerRadius:12];
    [win setContentView:bg];

    CGFloat padding = 20;

    // --- Top: title + subtitle ---
    CGFloat cursorY = h - padding;
    CGFloat titleH = 24;
    cursorY -= titleH;
    NSTextField *title = [NSTextField labelWithString:@"opcli access requested"];
    [title setFont:[NSFont systemFontOfSize:17 weight:NSFontWeightSemibold]];
    [title setTextColor:[NSColor labelColor]];
    [title setAlignment:NSTextAlignmentCenter];
    [title setFrame:NSMakeRect(padding, cursorY, w - padding * 2, titleH)];
    [bg addSubview:title];

    CGFloat subtitleH = 18;
    cursorY -= subtitleH + 2;
    NSString *subtitleText = [NSString stringWithFormat:@"request to read %ld %@",
                              (long)secretCount,
                              secretCount == 1 ? @"secret" : @"secrets"];
    NSTextField *subtitle = [NSTextField labelWithString:subtitleText];
    [subtitle setFont:[NSFont systemFontOfSize:12 weight:NSFontWeightRegular]];
    [subtitle setTextColor:[NSColor secondaryLabelColor]];
    [subtitle setAlignment:NSTextAlignmentCenter];
    [subtitle setFrame:NSMakeRect(padding, cursorY, w - padding * 2, subtitleH)];
    [bg addSubview:subtitle];

    // --- Bottom: cancel button + auth label + auth view ---
    CGFloat bottomY = padding;

    NSButton *cancel = [NSButton buttonWithTitle:@"Cancel"
                                          target:cancelTarget
                                          action:@selector(cancelClicked:)];
    [cancel setBezelStyle:NSBezelStyleRounded];
    [cancel setKeyEquivalent:@"\033"]; // Esc
    [cancel setFrame:NSMakeRect(padding, bottomY, 100, 28)];
    [bg addSubview:cancel];

    NSSize avSize = [authView fittingSize];
    if (avSize.width == 0 || avSize.height == 0) avSize = [authView frame].size;
    if (avSize.width == 0 || avSize.height == 0) avSize = NSMakeSize(32, 32);

    CGFloat authLabelH = 18;
    CGFloat authBlockTopPad = 14;
    CGFloat authLabelY = bottomY + 28 + authBlockTopPad;
    NSMutableAttributedString *authText = [[NSMutableAttributedString alloc]
        initWithString:@"Authorize with "
            attributes:@{NSFontAttributeName: [NSFont systemFontOfSize:12],
                         NSForegroundColorAttributeName: [NSColor labelColor]}];
    [authText appendAttributedString:[[NSAttributedString alloc]
        initWithString:@"Touch ID"
            attributes:@{NSFontAttributeName: [NSFont systemFontOfSize:12
                                                                 weight:NSFontWeightSemibold],
                         NSForegroundColorAttributeName: [NSColor labelColor]}]];
    NSTextField *authLabel = [NSTextField labelWithAttributedString:authText];
    [authLabel setAlignment:NSTextAlignmentCenter];
    [authLabel setFrame:NSMakeRect(padding, authLabelY, w - padding * 2, authLabelH)];
    [bg addSubview:authLabel];

    CGFloat authViewY = authLabelY + authLabelH + 6;
    CGFloat avX = (w - avSize.width) / 2;
    [authView setFrame:NSMakeRect(avX, authViewY, avSize.width, avSize.height)];
    [bg addSubview:authView];

    // --- Middle: refs list in an outer scroll view ---
    CGFloat refsTop = cursorY - 10;
    CGFloat refsBottom = authViewY + avSize.height + 18;
    CGFloat refsH = refsTop - refsBottom;

    NSScrollView *outerScroll = [[NSScrollView alloc] initWithFrame:
        NSMakeRect(padding, refsBottom, w - padding * 2, refsH)];
    [outerScroll setHasVerticalScroller:YES];
    [outerScroll setAutohidesScrollers:YES];
    [outerScroll setBorderType:NSNoBorder];
    [outerScroll setDrawsBackground:NO];

    NSView *groupedList = buildGroupedRefsList(groups, [outerScroll contentSize].width);
    [outerScroll setDocumentView:groupedList];

    [bg addSubview:outerScroll];

    return win;
}

@implementation OpcliAuthDelegate
- (void)applicationDidFinishLaunching:(NSNotification *)notification {
    self.context = [[LAContext alloc] init];

    NSError *canErr = nil;
    BOOL canBiometric = [self.context
        canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                    error:&canErr];
    if (!canBiometric) {
        // Fallback: no biometrics → classic alert flow, no custom window.
        [self.context evaluatePolicy:LAPolicyDeviceOwnerAuthentication
                     localizedReason:self.reason
                               reply:^(BOOL result, NSError *authError) {
            self.success = result;
            dispatch_async(dispatch_get_main_queue(), ^{ [self stopApp]; });
        }];
        return;
    }

    // Count secrets across all vault groups for the subtitle.
    NSInteger secretCount = 0;
    NSData *data = [self.refsJSON dataUsingEncoding:NSUTF8StringEncoding];
    NSArray *groups = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if ([groups isKindOfClass:[NSArray class]]) {
        for (NSDictionary *g in groups) {
            NSArray *refs = g[@"refs"];
            if ([refs isKindOfClass:[NSArray class]]) secretCount += refs.count;
        }
    }

    // .small (32x32) fingerprint — .regular (64x64) was reported as too
    // large against our window size.
    LAAuthenticationView *authView = [[LAAuthenticationView alloc]
        initWithContext:self.context controlSize:NSControlSizeSmall];

    self.window = buildAuthWindow(self.refsJSON, authView, secretCount, self);
    [self.window makeKeyAndOrderFront:nil];
    [NSApp activateIgnoringOtherApps:YES];

    [self.context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                 localizedReason:self.reason
                           reply:^(BOOL result, NSError *authError) {
        self.success = result;
        dispatch_async(dispatch_get_main_queue(), ^{ [self stopApp]; });
    }];
}

- (void)cancelClicked:(id)sender {
    // Invalidate the context so the pending evaluatePolicy reply fires with
    // a cancelation error; its callback will then call stopApp as normal.
    [self.context invalidate];
}

- (void)stopApp {
    if (self.window) {
        [self.window orderOut:nil];
        [self.window close];
        self.window = nil;
    }
    [NSApp stop:nil];
    // NSApp stop: only takes effect at the next event — post one so the
    // run loop wakes and actually returns.
    NSEvent *wake = [NSEvent otherEventWithType:NSEventTypeApplicationDefined
                                       location:NSZeroPoint
                                  modifierFlags:0
                                      timestamp:0
                                   windowNumber:0
                                        context:nil
                                        subtype:0
                                          data1:0
                                          data2:0];
    [NSApp postEvent:wake atStart:YES];
}
@end

// C interface for Go.
// If refsText is non-NULL and non-empty, an inline authorization window is
// shown listing the grouped refs. Otherwise, only the standard system
// prompt appears (no window).
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
        delegate.refsJSON = [NSString stringWithUTF8String:refsText];
        [NSApp setDelegate:delegate];
        [NSApp run];
        return delegate.success ? 0 : 1;
    }
}
