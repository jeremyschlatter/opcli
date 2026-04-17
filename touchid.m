//go:build !test

// TouchID authentication with an inline context window. The window shows:
//   - "opcli · access requested" title + a monospace sub-line identifying
//     the invoking command and tty
//   - vault-grouped list of op:// refs in a bordered box; the field (last
//     segment) of each ref is highlighted in the accent color so the reader
//     can scan for "what's being read"
//   - a footer caption noting that approval opens a 10-minute session
//   - Cancel button · "Authorize with Touch ID" label · LAAuthenticationView
//
// The window is chromeless (titlebar hidden) and uses a warm neutral dark
// panel. LAAuthenticationView renders Apple's fingerprint glyph inline — we
// only control its placement and size.
//
// Payload (JSON, passed from Go):
//   {"command":"claude deploy.sh", "tty":"ttys003",
//    "groups":[{"vault":"Employee","refs":["item/field", ...]}, ...]}
//
// Fallback: if biometrics aren't available the inline-window path is
// skipped entirely and we use the classic LAContext.evaluatePolicy
// dispatch-semaphore flow — no custom window, unstyled, but functional.

#import <AppKit/AppKit.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <LocalAuthenticationEmbeddedUI/LocalAuthenticationEmbeddedUI.h>
#import <dispatch/dispatch.h>

// Flipped NSView: y grows downward — simplifies top-down layout math.
@interface OpcliFlippedView : NSView
@end
@implementation OpcliFlippedView
- (BOOL)isFlipped { return YES; }
@end

@interface OpcliAuthDelegate : NSObject <NSApplicationDelegate>
@property(nonatomic, copy)   NSString  *reason;
@property(nonatomic, copy)   NSString  *payloadJSON;
@property(nonatomic, strong) LAContext *context;
@property(nonatomic, strong) NSWindow  *window;
@property(nonatomic, assign) BOOL       success;
- (void)cancelClicked:(id)sender;
@end

// —————————————————————————————————————————————————————————————
// Design palette (from the Claude Design handoff). Accent hue 215 in oklch
// — a soft sky-cyan, converted once to sRGB here.
// —————————————————————————————————————————————————————————————
static NSColor *colorPanel(void)        { return [NSColor colorWithSRGBRed:0.090 green:0.075 blue:0.059 alpha:1.0]; } // #17130f
static NSColor *colorBox(void)          { return [NSColor colorWithSRGBRed:0.118 green:0.102 blue:0.086 alpha:1.0]; } // #1e1a16
static NSColor *colorStroke(void)       { return [NSColor colorWithSRGBRed:1.000 green:0.941 blue:0.863 alpha:0.08]; }
static NSColor *colorText(void)         { return [NSColor colorWithSRGBRed:0.957 green:0.929 blue:0.886 alpha:1.0]; }
static NSColor *colorTextDim(void)      { return [NSColor colorWithSRGBRed:0.655 green:0.624 blue:0.573 alpha:1.0]; }
static NSColor *colorTextFaint(void)    { return [NSColor colorWithSRGBRed:0.420 green:0.396 blue:0.357 alpha:1.0]; }
static NSColor *colorAccent(void)       { return [NSColor colorWithSRGBRed:0.171 green:0.799 blue:0.922 alpha:1.0]; } // oklch(0.78 0.13 215)

static NSFont *fontUI(CGFloat sz, NSFontWeight w)   { return [NSFont systemFontOfSize:sz weight:w]; }
static NSFont *fontMono(CGFloat sz, NSFontWeight w) { return [NSFont monospacedSystemFontOfSize:sz weight:w]; }

// Render a single ref (passed in as "item/[section/]field" — already
// stripped of "op://vault/") as an attributed string:
//   last segment (field)   → accent + semibold
//   first segment (item)   → bright text
//   middle segments        → dim text
//   slashes                → faint
static NSAttributedString *renderRefAttr(NSString *ref) {
    NSArray<NSString *> *parts = [ref componentsSeparatedByString:@"/"];
    NSMutableAttributedString *out = [[NSMutableAttributedString alloc] init];
    NSUInteger n = parts.count;
    for (NSUInteger i = 0; i < n; i++) {
        NSColor *c;
        NSFont  *f = fontMono(12, NSFontWeightRegular);
        if (i == n - 1) { c = colorAccent(); f = fontMono(12, NSFontWeightSemibold); }
        else if (i == 0) { c = colorText(); }
        else { c = colorTextDim(); }
        [out appendAttributedString:[[NSAttributedString alloc] initWithString:parts[i] attributes:@{
            NSFontAttributeName: f,
            NSForegroundColorAttributeName: c,
        }]];
        if (i < n - 1) {
            [out appendAttributedString:[[NSAttributedString alloc] initWithString:@"/" attributes:@{
                NSFontAttributeName: fontMono(12, NSFontWeightRegular),
                NSForegroundColorAttributeName: colorTextFaint(),
            }]];
        }
    }
    return out;
}

// Header: "opcli · access requested" title + optional monospace sub-line
// "$ <command>  ·  <tty>". Either command or tty may be empty; the sub-line
// is suppressed if both are.
static NSView *buildHeader(NSString *command, NSString *tty, CGFloat width) {
    OpcliFlippedView *v = [[OpcliFlippedView alloc] initWithFrame:NSMakeRect(0,0,width,0)];

    NSMutableAttributedString *title = [[NSMutableAttributedString alloc] init];
    [title appendAttributedString:[[NSAttributedString alloc] initWithString:@"opcli" attributes:@{
        NSFontAttributeName: fontUI(15, NSFontWeightSemibold),
        NSForegroundColorAttributeName: colorText(),
    }]];
    [title appendAttributedString:[[NSAttributedString alloc] initWithString:@"   ·   " attributes:@{
        NSFontAttributeName: fontUI(15, NSFontWeightRegular),
        NSForegroundColorAttributeName: colorTextFaint(),
    }]];
    [title appendAttributedString:[[NSAttributedString alloc] initWithString:@"access requested" attributes:@{
        NSFontAttributeName: fontUI(15, NSFontWeightMedium),
        NSForegroundColorAttributeName: colorTextDim(),
    }]];
    NSTextField *titleField = [NSTextField labelWithAttributedString:title];
    [titleField setFrame:NSMakeRect(0, 0, width, 20)];
    [v addSubview:titleField];

    CGFloat y = 22;
    if (command.length || tty.length) {
        NSMutableAttributedString *sub = [[NSMutableAttributedString alloc] init];
        if (command.length) {
            [sub appendAttributedString:[[NSAttributedString alloc] initWithString:@"$ " attributes:@{
                NSFontAttributeName: fontMono(12, NSFontWeightRegular),
                NSForegroundColorAttributeName: colorTextFaint(),
            }]];
            [sub appendAttributedString:[[NSAttributedString alloc] initWithString:command attributes:@{
                NSFontAttributeName: fontMono(12, NSFontWeightRegular),
                NSForegroundColorAttributeName: colorTextDim(),
            }]];
        }
        if (command.length && tty.length) {
            [sub appendAttributedString:[[NSAttributedString alloc] initWithString:@" · " attributes:@{
                NSFontAttributeName: fontMono(12, NSFontWeightRegular),
                NSForegroundColorAttributeName: colorTextFaint(),
            }]];
        }
        if (tty.length) {
            [sub appendAttributedString:[[NSAttributedString alloc] initWithString:tty attributes:@{
                NSFontAttributeName: fontMono(12, NSFontWeightRegular),
                NSForegroundColorAttributeName: colorTextDim(),
            }]];
        }
        NSTextField *subField = [NSTextField labelWithAttributedString:sub];
        [subField setLineBreakMode:NSLineBreakByTruncatingTail];
        [subField setFrame:NSMakeRect(0, y, width, 16)];
        [v addSubview:subField];
        y += 18;
    }

    [v setFrame:NSMakeRect(0, 0, width, y)];
    return v;
}

// One vault section inside the secrets box: header line + one row per ref.
static NSView *buildVaultSection(NSString *vault, NSArray<NSString *> *refs, CGFloat contentW) {
    OpcliFlippedView *v = [[OpcliFlippedView alloc] initWithFrame:NSMakeRect(0,0,contentW,0)];
    CGFloat hPad = 12;
    CGFloat bulletCol = 16;
    CGFloat gap = 8;
    CGFloat y = 10;

    // Vault header: "<vault>   · <N>"
    NSMutableAttributedString *hdr = [[NSMutableAttributedString alloc] init];
    [hdr appendAttributedString:[[NSAttributedString alloc] initWithString:vault attributes:@{
        NSFontAttributeName: fontUI(12, NSFontWeightSemibold),
        NSForegroundColorAttributeName: colorText(),
    }]];
    [hdr appendAttributedString:[[NSAttributedString alloc] initWithString:
        [NSString stringWithFormat:@" · %lu", (unsigned long)refs.count] attributes:@{
        NSFontAttributeName: fontMono(11, NSFontWeightRegular),
        NSForegroundColorAttributeName: colorTextFaint(),
    }]];
    NSTextField *hdrField = [NSTextField labelWithAttributedString:hdr];
    [hdrField setFrame:NSMakeRect(hPad, y, contentW - 2*hPad, 16)];
    [v addSubview:hdrField];
    y += 16 + 6;

    CGFloat pathX = hPad + bulletCol + gap;
    CGFloat pathW = contentW - pathX - hPad;

    for (NSString *r in refs) {
        NSAttributedString *attr = renderRefAttr(r);

        NSTextField *path = [NSTextField wrappingLabelWithString:@""];
        [path setAttributedStringValue:attr];
        [path setSelectable:YES];
        [path setToolTip:[NSString stringWithFormat:@"op://%@/%@", vault, r]];
        NSSize sz = [path sizeThatFits:NSMakeSize(pathW, CGFLOAT_MAX)];
        CGFloat h = MAX(18, ceil(sz.height));
        [path setFrame:NSMakeRect(pathX, y, pathW, h)];
        [v addSubview:path];

        NSTextField *bullet = [NSTextField labelWithAttributedString:
            [[NSAttributedString alloc] initWithString:@"›" attributes:@{
                NSFontAttributeName: fontMono(10, NSFontWeightRegular),
                NSForegroundColorAttributeName: colorTextFaint(),
            }]];
        [bullet setAlignment:NSTextAlignmentCenter];
        [bullet setFrame:NSMakeRect(hPad + 6, y + 2, bulletCol, 14)];
        [v addSubview:bullet];

        y += h + 4;
    }
    y += 4;
    [v setFrame:NSMakeRect(0, 0, contentW, y)];
    return v;
}

// Full secrets list: vault sections stacked with hairline dividers.
static NSView *buildSecretsList(NSArray *groups, CGFloat contentW) {
    OpcliFlippedView *v = [[OpcliFlippedView alloc] initWithFrame:NSMakeRect(0,0,contentW,0)];
    CGFloat y = 0;
    for (NSUInteger i = 0; i < groups.count; i++) {
        NSDictionary *g = groups[i];
        NSArray *refs = g[@"refs"];
        if (![refs isKindOfClass:[NSArray class]]) refs = @[];
        NSString *vault = g[@"vault"] ?: @"";

        if (i > 0) {
            // Hairline divider between vaults (design uses a dashed line;
            // a solid 1px rule reads the same at this size).
            NSView *div = [[NSView alloc] initWithFrame:NSMakeRect(6, y, contentW - 12, 1)];
            [div setWantsLayer:YES];
            [div.layer setBackgroundColor:[colorStroke() CGColor]];
            [v addSubview:div];
            y += 1;
        }
        NSView *section = buildVaultSection(vault, refs, contentW);
        [section setFrameOrigin:NSMakePoint(0, y)];
        [v addSubview:section];
        y += section.frame.size.height;
    }
    [v setFrame:NSMakeRect(0, 0, contentW, y)];
    return v;
}

// The boxed secrets container: rounded background + border + an inner
// scroll view that clips content to 260px max height.
static NSView *buildSecretsBox(NSArray *groups, CGFloat width) {
    NSView *list = buildSecretsList(groups, width);
    CGFloat listH = list.frame.size.height;
    CGFloat maxH  = 260;
    CGFloat boxH  = MIN(listH, maxH);

    NSView *box = [[NSView alloc] initWithFrame:NSMakeRect(0,0,width,boxH)];
    [box setWantsLayer:YES];
    [box.layer setBackgroundColor:[colorBox() CGColor]];
    [box.layer setBorderColor:[colorStroke() CGColor]];
    [box.layer setBorderWidth:1.0];
    [box.layer setCornerRadius:10.0];
    [box.layer setMasksToBounds:YES];

    NSScrollView *scroll = [[NSScrollView alloc] initWithFrame:NSMakeRect(0,0,width,boxH)];
    [scroll setHasVerticalScroller:YES];
    [scroll setAutohidesScrollers:YES];
    [scroll setBorderType:NSNoBorder];
    [scroll setDrawsBackground:NO];
    [scroll setDocumentView:list];
    [box addSubview:scroll];

    return box;
}

// Footer caption: "Also grants this terminal 10 min of unprompted access to
// any secret." "10 min" is emphasized slightly so the duration pops.
static NSView *buildFooterCaption(CGFloat contentW) {
    NSDictionary *faint = @{
        NSFontAttributeName: fontMono(11, NSFontWeightRegular),
        NSForegroundColorAttributeName: colorTextFaint(),
    };
    NSDictionary *emph = @{
        NSFontAttributeName: fontMono(11, NSFontWeightSemibold),
        NSForegroundColorAttributeName: colorTextDim(),
    };
    NSMutableAttributedString *a = [[NSMutableAttributedString alloc] init];
    [a appendAttributedString:[[NSAttributedString alloc] initWithString:@"Also grants this terminal " attributes:faint]];
    [a appendAttributedString:[[NSAttributedString alloc] initWithString:@"10 min" attributes:emph]];
    [a appendAttributedString:[[NSAttributedString alloc] initWithString:@" of unprompted access to any secret." attributes:faint]];

    NSTextField *f = [NSTextField wrappingLabelWithString:@""];
    [f setAttributedStringValue:a];
    NSSize sz = [f sizeThatFits:NSMakeSize(contentW, CGFLOAT_MAX)];
    CGFloat h = ceil(sz.height);
    [f setFrame:NSMakeRect(0, 0, contentW, h)];
    return f;
}

// Bottom auth row: Cancel (left) · flex spacer · "Authorize with Touch ID"
// label · LAAuthenticationView (right).
static NSView *buildAuthRow(NSView *authView, id cancelTarget, CGFloat windowW) {
    CGFloat hPad = 18;
    CGFloat rowH = 34;
    NSView *row = [[NSView alloc] initWithFrame:NSMakeRect(0,0,windowW,rowH)];

    NSButton *cancel = [NSButton buttonWithTitle:@"Cancel" target:cancelTarget action:@selector(cancelClicked:)];
    [cancel setBezelStyle:NSBezelStyleRounded];
    [cancel setKeyEquivalent:@"\033"]; // Esc
    NSSize cSize = [cancel fittingSize];
    if (cSize.width < 80) cSize.width = 80;
    [cancel setFrame:NSMakeRect(hPad, (rowH - cSize.height) / 2, cSize.width, cSize.height)];
    [row addSubview:cancel];

    NSSize avSize = [authView fittingSize];
    if (avSize.width == 0 || avSize.height == 0) avSize = [authView frame].size;
    if (avSize.width == 0 || avSize.height == 0) avSize = NSMakeSize(32, 32);
    CGFloat avX = windowW - hPad - avSize.width;
    [authView setFrame:NSMakeRect(avX, (rowH - avSize.height) / 2, avSize.width, avSize.height)];
    [row addSubview:authView];

    NSMutableAttributedString *lbl = [[NSMutableAttributedString alloc] init];
    [lbl appendAttributedString:[[NSAttributedString alloc] initWithString:@"Authorize with " attributes:@{
        NSFontAttributeName: fontUI(13, NSFontWeightRegular),
        NSForegroundColorAttributeName: colorTextDim(),
    }]];
    [lbl appendAttributedString:[[NSAttributedString alloc] initWithString:@"Touch ID" attributes:@{
        NSFontAttributeName: fontUI(13, NSFontWeightSemibold),
        NSForegroundColorAttributeName: colorText(),
    }]];
    NSTextField *label = [NSTextField labelWithAttributedString:lbl];
    NSSize lSize = [label fittingSize];
    CGFloat lX = avX - 10 - lSize.width;
    [label setFrame:NSMakeRect(lX, (rowH - lSize.height) / 2, lSize.width, lSize.height)];
    [row addSubview:label];

    return row;
}

static NSWindow *buildAuthWindow(NSString *payloadJSON, NSView *authView, id cancelTarget) {
    NSData *data = [payloadJSON dataUsingEncoding:NSUTF8StringEncoding];
    id obj = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    NSDictionary *payload = [obj isKindOfClass:[NSDictionary class]] ? obj : @{};
    NSString *command = payload[@"command"]; if (![command isKindOfClass:[NSString class]]) command = @"";
    NSString *tty     = payload[@"tty"];     if (![tty     isKindOfClass:[NSString class]]) tty = @"";
    NSArray  *groups  = payload[@"groups"];  if (![groups  isKindOfClass:[NSArray  class]]) groups = @[];

    CGFloat w = 440;
    CGFloat hPad = 22;
    CGFloat contentW = w - 2*hPad;

    NSView *header     = buildHeader(command, tty, contentW);
    NSView *secretsBox = buildSecretsBox(groups, contentW);
    NSView *caption    = buildFooterCaption(contentW);
    NSView *authRow    = buildAuthRow(authView, cancelTarget, w);

    CGFloat headerH  = header.frame.size.height;
    CGFloat boxH     = secretsBox.frame.size.height;
    CGFloat captionH = caption.frame.size.height;
    CGFloat authRowH = authRow.frame.size.height;

    CGFloat topPad         = 20;
    CGFloat bottomPad      = 16;
    CGFloat gapHeadBox     = 14;
    CGFloat gapBoxCaption  = 14;
    CGFloat gapCaptionAuth = 12;
    CGFloat totalH = topPad + headerH + gapHeadBox + boxH + gapBoxCaption
                   + captionH + gapCaptionAuth + authRowH + bottomPad;

    NSScreen *screen = [NSScreen mainScreen] ?: [[NSScreen screens] firstObject];
    NSRect sf = screen ? [screen visibleFrame] : NSMakeRect(0,0,1440,900);
    NSRect frame = NSMakeRect(NSMidX(sf) - w/2, NSMidY(sf) - totalH/2, w, totalH);

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
    // Force dark appearance — we want the same panel regardless of system
    // Light/Dark mode.
    [win setAppearance:[NSAppearance appearanceNamed:NSAppearanceNameDarkAqua]];

    OpcliFlippedView *root = [[OpcliFlippedView alloc] initWithFrame:NSMakeRect(0,0,w,totalH)];
    [root setWantsLayer:YES];
    [root.layer setBackgroundColor:[colorPanel() CGColor]];
    [win setContentView:root];

    CGFloat y = topPad;
    [header setFrameOrigin:NSMakePoint(hPad, y)];      [root addSubview:header];     y += headerH + gapHeadBox;
    [secretsBox setFrameOrigin:NSMakePoint(hPad, y)];  [root addSubview:secretsBox]; y += boxH + gapBoxCaption;
    [caption setFrameOrigin:NSMakePoint(hPad, y)];     [root addSubview:caption];    y += captionH + gapCaptionAuth;
    [authRow setFrameOrigin:NSMakePoint(0, y)];        [root addSubview:authRow];

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

    // .small (32x32) matches the design; .regular (64x64) is too large
    // against our window size.
    LAAuthenticationView *authView = [[LAAuthenticationView alloc]
        initWithContext:self.context controlSize:NSControlSizeSmall];

    self.window = buildAuthWindow(self.payloadJSON, authView, self);
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
// shown. Otherwise, only the standard system prompt appears (no window).
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
        delegate.payloadJSON = [NSString stringWithUTF8String:refsText];
        [NSApp setDelegate:delegate];
        [NSApp run];
        return delegate.success ? 0 : 1;
    }
}
